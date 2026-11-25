# A long valkey-benchmark fuzzer run, used by the Fuzz workflow
# (.github/workflows/fuzz.yml). It only runs with --fuzz-soak, for example:
#
#   ./runtest --single unit/fuzz-soak --fuzz-soak --fuzz-setup cluster \
#       --fuzz-mode malformed-commands --fuzz-duration 60 --fuzz-seed 12345
#
# The test fails if a server crashes or asserts, sends a malformed reply, hangs,
# or doesn't answer PING at the end. A sanitizer report in a server's stderr
# fails the run when the server is stopped. The fuzzer's command line and output
# are kept in tests/tmp/fuzz-soak.*/ (use --dont-clean to keep them after the run).

# Run the fuzzer against the servers of the current start_server or
# start_cluster block, then check its outcome and the servers.
proc fuzz_soak {nodes} {
    set args [list -p [srv 0 port] -c 20 --duration $::fuzz_duration --fuzz --fuzz-loglevel info]
    if {$nodes > 1} {lappend args --cluster}
    if {$::fuzz_mode ne "default"} {lappend args --fuzz-mode $::fuzz_mode}
    if {$::fuzz_seed ne ""} {lappend args --seed $::fuzz_seed}
    set cmd [list $::VALKEY_BENCHMARK_BIN {*}$args]

    set dir [tmpdir fuzz-soak]
    set output [file join $dir output.txt]
    set fd [open [file join $dir command.txt] w]
    puts $fd $cmd
    close $fd
    puts "Fuzzer command: $cmd"
    puts "Fuzzer output: $output"

    set code 0
    if {[catch {exec {*}$cmd >& $output} err opts]} {
        set errorcode [dict get $opts -errorcode]
        if {[lindex $errorcode 0] ne "CHILDSTATUS"} {
            fail "valkey-benchmark did not exit normally: $err"
        }
        set code [lindex $errorcode 2]
    }

    # The fuzzer prints its seed first and its outcome last, each on its own line.
    catch {puts [exec grep -a -m 1 {^Fuzz seed:} $output]}
    set outcome {}
    catch {set outcome [exec grep -a {^Fuzz outcome:} $output]}
    puts $outcome

    # Outcomes are listed in fuzzer_client.c (FuzzOutcome). Only "some clients
    # timed out" (5) is not a failure: for example, one client can wait on a
    # fuzzed BLPOP with a long timeout that nobody serves.
    set problems {}
    if {![regexp {\(exit code (\d+)\)$} $outcome -> reported]} {
        lappend problems "valkey-benchmark exited with code $code and printed no outcome"
    } elseif {$reported != $code} {
        lappend problems "valkey-benchmark exited with code $code but printed '$outcome'"
    } elseif {$code == 5} {
        catch {puts [exec grep -a {TIMEOUT:} $output]}
    } elseif {$code != 0} {
        lappend problems $outcome
    }

    # The servers must still answer, and not have logged a crash report, which
    # also covers a crash after the clients finished or in a forked child.
    # Skip PING after a hang: the test client has no timeout.
    for {set j 0} {$j < $nodes} {incr j} {
        if {[count_log_message -$j "BUG REPORT START"] > 0} {
            lappend problems "server $j logged a crash report"
            puts [crashlog_from_file [srv -$j stdout]]
        }
        if {$code == 4} continue
        if {[catch {reconnect -$j; [srv -$j client] ping} reply] || $reply ne {PONG}} {
            lappend problems "server $j did not answer PING: $reply"
        }
    }
    if {[llength $problems] > 0} {
        fail [join $problems "; "]
    }
}

run_solo {fuzz-soak} {
tags {"fuzz-soak external:skip"} {
    if {[lsearch -exact {default malformed-commands config-commands} $::fuzz_mode] < 0} {
        error "--fuzz-mode must be default, malformed-commands or config-commands"
    }
    if {![string is integer -strict $::fuzz_duration] || $::fuzz_duration <= 0} {
        error "--fuzz-duration must be a number of seconds"
    }
    if {$::fuzz_seed ne "" && ![regexp {^[0-9]+$} $::fuzz_seed]} {
        error "--fuzz-seed must be a number"
    }

    # The memory test in a crash report reads every anonymous mapping, which ASan
    # reports as an error of its own, after the real crash.
    set overrides {crash-memcheck-enabled no}
    if {$::fuzz_setup eq "standalone"} {
        start_server [list overrides $overrides] {
            test "FUZZ soak: standalone, $::fuzz_mode mode, $::fuzz_duration seconds" {
                fuzz_soak 1
            }
        }
    } elseif {$::fuzz_setup eq "cluster"} {
        start_cluster 3 0 [list tags {cluster} overrides $overrides] {
            test "FUZZ soak: 3 primaries, $::fuzz_mode mode, $::fuzz_duration seconds" {
                fuzz_soak 3
            }
        }
    } else {
        error "--fuzz-setup must be standalone or cluster"
    }
}
}
