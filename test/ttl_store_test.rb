# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "rodauth/oauth" # bootstraps the Rodauth::OAuth namespace so the test loads standalone
require "rodauth/oauth/ttl_store"

class RodauthOAuthTtlStoreTest < Minitest::Test
  # The TtlStore is used read-first: callers do `store[key]` and, on a miss,
  # populate it via `store.set(key) { [payload, duration] }`. The block returns
  # a TTL *duration* (in seconds), which the store turns into an absolute
  # monotonic deadline. These tests stub the private #now to drive time
  # deterministically, independent of the real monotonic clock.

  # (a) Within the TTL window, the populate block runs exactly ONCE even across
  # several read-first accesses.
  def test_block_runs_once_within_ttl_window
    store = build_store(1000.0)
    calls = 0
    fetch = read_first(store) do
      calls += 1
      ["payload", 60] # 60-second TTL duration => deadline at 1060
    end

    assert_equal "payload", fetch.call
    assert_equal "payload", fetch.call

    set_clock(store, 1030.0) # still inside the 60s window
    assert_equal "payload", fetch.call
    set_clock(store, 1059.0) # t < deadline (1060)
    assert_equal "payload", fetch.call

    assert_equal 1, calls, "block should have run exactly once within the TTL window"
  end

  # (b) Once the deadline passes, the value is considered stale and the block
  # runs again (refetch).
  def test_block_runs_again_after_deadline
    store = build_store(1000.0)
    calls = 0
    fetch = read_first(store) do
      calls += 1
      ["payload-#{calls}", 60]
    end

    assert_equal "payload-1", fetch.call
    assert_equal 1, calls

    set_clock(store, 1061.0) # past the deadline (1060)
    assert_equal "payload-2", fetch.call
    assert_equal 2, calls, "block should refetch once the deadline has passed"
  end

  # (c) The behaviour must not depend on the magnitude of the monotonic clock.
  # The original bug compared a raw duration against CLOCK_MONOTONIC, so it
  # behaved differently depending on system uptime. Run the same scenario with
  # several clock bases to prove correctness is uptime-independent.
  def test_freshness_is_independent_of_monotonic_clock_magnitude
    [0.5, 1_000.0, 9_999_999.0].each do |base|
      store = build_store(base)
      calls = 0
      fetch = read_first(store) do
        calls += 1
        ["payload", 60]
      end

      assert_equal "payload", fetch.call
      set_clock(store, base + 59) # still fresh
      assert_equal "payload", fetch.call
      assert_equal 1, calls, "block should run once within window (clock base #{base})"

      set_clock(store, base + 61) # past the 60s deadline
      assert_equal "payload", fetch.call
      assert_equal 2, calls, "block should refetch after deadline (clock base #{base})"
    end
  end

  private

  # Build a store whose private #now returns a settable value we control.
  def build_store(initial)
    store = Rodauth::OAuth::TtlStore.new
    store.instance_variable_set(:@test_clock, initial)
    store.define_singleton_method(:now) { @test_clock }
    store
  end

  def set_clock(store, value)
    store.instance_variable_set(:@test_clock, value)
  end

  # Returns a lambda implementing the real read-first usage pattern:
  # read via [], and on a miss populate via set { [payload, duration] }.
  def read_first(store, &populate)
    -> { store[:key] || store.set(:key, &populate) }
  end
end
