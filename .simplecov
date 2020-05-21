SimpleCov.start do
  command_name "Minitest"
  add_filter "/.bundle/"
  add_filter "/vendor/"
  add_filter "/test/"
  minimum_coverage 80
end
