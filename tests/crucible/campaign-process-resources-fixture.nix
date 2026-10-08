# Exercises the service schema and partition checks without starting SQLite.
# These values are evaluation fixtures, not a native initialization bound or
# a qualified deployment policy.
{
  memoryMaxBytes = 67108864;
  tasksMax = 8;
  fileDescriptors = 64;
  runtimeSeconds = 60;
  startupTimeoutSeconds = 30;
  mainThreadStackBytes = 1048576;
  cpuQuotaPercent = 200;
  baselineResidentBytes = 16777216;
  metadataBytes = 8388608;
  sqliteBootstrapBytes = 1048576;
  sqliteHeapBytes = 8388608;
  sqliteConnections = 16;
  workerThreads = 2;
  blockingThreads = 2;
  threadStackBytes = 1048576;
}
