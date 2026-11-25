tags {"slow"} {
    run_solo {fuzzer} {
        start_server {} {
            test {FUZZ stresser with valkey-benchmark} {
                assert_equal [r ping] {PONG}
                set err [catch {exec $::VALKEY_BENCHMARK_BIN -p [srv 0 port] -c 20 -n 100000 --fuzz --fuzz-loglevel info} output]
                if {$err && $::verbose} {
                    # For now, if the server is still responsive, we don't consider the test a failure even if the fuzzer failed.
                    puts $output
                }
                # Verify server is still responsive after the fuzzer run
                # Create a new client connection in case the previous one was closed by the fuzzer.
                set rr [valkey_client]
                assert_equal [$rr ping] {PONG}
            }
        }
    }

    run_solo {fuzzer-cluster} {
        start_cluster 3 0 {tags {"external:skip cluster"}} {
            test {FUZZ stresser with valkey-benchmark in cluster mode} {
                # The fuzzer sends CONFIG RESETSTAT, so INFO commandstats can't tell
                # which nodes ran commands. Use the count of writes since the last
                # save instead, which it doesn't reset.
                for {set j 0} {$j < 3} {incr j} {
                    set dirty($j) [s -$j rdb_changes_since_last_save]
                }
                set err [catch {exec $::VALKEY_BENCHMARK_BIN -p [srv 0 port] --cluster -c 20 -n 20000 --fuzz --fuzz-loglevel info} output]
                if {$err && $::verbose} {
                    puts $output
                }
                # Every primary ran fuzzed writes and the cluster is still healthy.
                # Reconnect first in case the fuzzer killed the test clients.
                for {set j 0} {$j < 3} {incr j} {
                    reconnect -$j
                    assert_morethan [s -$j rdb_changes_since_last_save] $dirty($j)
                }
                wait_for_cluster_state ok
            }
        }
    }

    # Run the fuzzer and return its output. Check that the "Fuzz outcome" line
    # and the exit code agree.
    proc run_fuzzer {args} {
        set code 0
        if {[catch {exec $::VALKEY_BENCHMARK_BIN --fuzz {*}$args 2>@1} output opts]} {
            set code [lindex [dict get $opts -errorcode] 2]
        }
        assert_match "*Fuzz outcome: * (exit code $code)*" $output
        return $output
    }

    start_server {tags {"external:skip"}} {
        start_server {} {
            test {FUZZ valkey-benchmark prints a seed that replays the run} {
                # Run once without --seed, then replay the printed seed on another
                # server. With one client the commands are the same, apart from
                # unix-time arguments, which are relative to the current time.
                set args {-c 1 -n 500 --fuzz-loglevel debug}
                set out1 [run_fuzzer -p [srv -1 port] {*}$args]
                assert {[regexp {Fuzz seed: (\d+)} $out1 -> seed]}
                set out2 [run_fuzzer -p [srv 0 port] {*}$args --seed $seed]
                assert_match "*Fuzz seed: $seed*" $out2
                foreach i {1 2} {
                    set sent [regexp -all -inline -line {send Command: .*$} [set out$i]]
                    set sent$i [regsub -all {\m\d{10}\M} $sent T]
                }
                assert_morethan [llength $sent1] 250
                assert_equal $sent1 $sent2
            }

            test {FUZZ valkey-benchmark stops after --duration} {
                set start [clock milliseconds]
                set output [run_fuzzer -p [srv 0 port] -c 4 --duration 5]
                set elapsed [expr {[clock milliseconds] - $start}]
                assert_match "*Running fuzzer with 4 clients for 5 seconds*" $output
                # A client can wait up to 15 seconds for one reply before it gives up.
                assert_morethan_equal $elapsed 5000
                assert_lessthan $elapsed 25000
            }
        }
    }
}
