// Copyright 2018 RetailNext, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iptables

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const countersRegexp = `^\[(\d+):(\d+)]$`

func ParseIptablesSave(r io.Reader) (Tables, error) {
	scanner := bufio.NewScanner(r)
	parser := parser{}

	for scanner.Scan() {
		parser.handleLine(scanner.Text())
	}

	parser.flush()
	if parser.err != nil {
		slog.Error("failed to parse iptables-save", slog.String("err", parser.err.Error()))
		return nil, parser.err
	}

	if err := scanner.Err(); err != nil {
		slog.Error("failed to read iptables-save", slog.String("err", err.Error()))
		return nil, err
	}

	return parser.result, nil
}

type ParseError struct {
	Message    string
	LineNumber int
	LineText   string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("%s at line %d: %+v", e.Message, e.LineNumber, e.LineText)
}

type parser struct {
	result           Tables
	currentTableName string
	currentTable     Table
	line             int
	err              error
}

func (p *parser) flush() {
	if p.currentTableName != "" {
		if p.result == nil {
			p.result = make(Tables)
		}
		p.result[p.currentTableName] = p.currentTable
		p.currentTableName = ""
		p.currentTable = nil
	}
}

func (p *parser) handleNewChain(line string) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		p.err = errors.Join(p.err, ParseError{"expected 3 fields", p.line, line})
		return
	}
	name := strings.TrimPrefix(fields[0], ":")
	packets, bytes, ok := parseCounters(fields[2])
	if !ok {
		p.err = errors.Join(p.err, ParseError{"expected [packets:bytes]", p.line, line})
		return
	}
	if p.currentTable == nil {
		p.currentTable = make(map[string]Chain)
	}
	chain := Chain{
		Policy:  fields[1],
		Packets: packets,
		Bytes:   bytes,
	}
	p.currentTable[name] = chain
}

func (p *parser) handleRule(line string) {
	fields := strings.Fields(line)
	subParser := ruleParser{}
	for _, token := range fields {
		subParser.handleToken(token)
	}
	subParser.flush()
	if !subParser.countersOk {
		p.err = errors.Join(p.err, ParseError{"expected [packets:bytes]", p.line, line})
		return
	}
	if subParser.chain == "" {
		p.err = errors.Join(p.err, ParseError{"expected -A chain ...", p.line, line})
		return
	}
	r := Rule{
		Packets: subParser.packets,
		Bytes:   subParser.bytes,
		Rule:    strings.Join(subParser.flags, " "),
	}
	chain := p.currentTable[subParser.chain]

	// Filtering mechanism to prevent multiple duplicate rules to get created.
	// We simply skip addition of the rule if it already exists in the chain.
	// Note: We considering ONLY rule to uniquely identify it, and NOT packets and bytes.
	doesRuleExistInChain := func(rule Rule) bool {
		return rule.Rule == r.Rule
	}
	if slices.ContainsFunc(chain.Rules, doesRuleExistInChain) {
		return
	}

	chain.Rules = append(chain.Rules, r)
	p.currentTable[subParser.chain] = chain
}

func (p *parser) handleLine(line string) {
	p.line++
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	if line == "COMMIT" {
		p.flush()
		return
	}
	if name := strings.TrimPrefix(line, "*"); name != line {
		p.flush()
		p.currentTableName = name
		return
	}
	if strings.HasPrefix(line, ":") {
		p.handleNewChain(line)
		return
	}
	if strings.HasPrefix(line, "[") {
		p.handleRule(line)
		return
	}
	p.err = errors.Join(p.err, ParseError{"unhandled line", p.line, line})
}

func parseCounters(field string) (packets, bytes uint64, ok bool) {
	parts := regexp.MustCompile(countersRegexp).FindStringSubmatch(field)
	if len(parts) != 3 {
		return
	}
	var packetsErr, bytesErr error
	packets, packetsErr = strconv.ParseUint(parts[1], 10, 64)
	bytes, bytesErr = strconv.ParseUint(parts[2], 10, 64)
	ok = packetsErr == nil && bytesErr == nil
	return
}
