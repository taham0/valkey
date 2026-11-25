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
}
