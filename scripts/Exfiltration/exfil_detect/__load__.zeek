#
# This is processed when a user explicitly loads the plugin's script module
# through `@load <plugin-namespace>/<plugin-name>`. Include code here that
# should execute at that point. This is the most common entry point to
# your plugin's accompanying scripts.
#

@load ./main
@load ./baseline
@load ./baseline_persistance
@load ./pcr
@load ./zscore
@load ./euclidean
@load ./new_proto
@load ./finalize
@load ./monitoring

