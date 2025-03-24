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
	"log/slog"
	"os/exec"
)

func GetTables() (Tables, error) {
	cmd := exec.Command("iptables-save", "-c")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		slog.Error("failed to pipe iptables-save output", slog.String("err", err.Error()))
		return nil, err
	}

	type resultNErr struct {
		Tables
		error
	}

	resultCh := make(chan resultNErr)
	go func() {
		result, parseErr := ParseIptablesSave(pipe)
		resultCh <- resultNErr{result, parseErr}
	}()

	err = cmd.Start()
	if err != nil {
		slog.Error("failed to start iptables-save", slog.String("err", err.Error()))
		return nil, err
	}

	r := <-resultCh
	err = cmd.Wait()
	if err != nil {
		slog.Error("iptables-save encountered failure", slog.String("err", err.Error()))
		return nil, err
	}

	return r.Tables, r.error
}
