# frozen_string_literal: true

#
# The TTL store is a data structure which keeps data by a key, and with a time-to-live.
# It is specifically designed for data which is static, i.e. for a certain key in a
# sufficiently large span, the value will be the same.
#
# Because of that, synchronizations around reads do not exist, while write synchronizations
# will be short-circuited by a read.
#
class Rodauth::OAuth::TtlStore
  DEFAULT_TTL = 60 * 60 * 24 # default TTL is one day

  def initialize
    @store_mutex = Mutex.new
    @store = Hash.new {}
  end

  def [](key)
    lookup(key, now)
  end

  def set(key, ttl = nil, &payload)
    @store_mutex.synchronize do
      # short circuit
      return @store[key][:payload] if @store[key] && @store[key][:ttl] < now

      @store[key] = { payload: payload.call, ttl: (ttl || (now + DEFAULT_TTL)) }

      @store[key][:payload]
    end
  end

  def uncache(key)
    @store_mutex.synchronize do
      @store.delete(key)
    end
  end

  private

  def now
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  # do not use directly!
  def lookup(key, ttl)
    return unless @store.key?(key)

    value = @store[key]

    return if value.empty?

    return unless value[:ttl] > ttl

    value[:payload]
  end
end
