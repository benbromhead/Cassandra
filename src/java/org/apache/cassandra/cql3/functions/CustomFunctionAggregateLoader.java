package org.apache.cassandra.cql3.functions;

import java.util.List;

public interface CustomFunctionAggregateLoader
{
    public List<Function> getFunctions();
}
