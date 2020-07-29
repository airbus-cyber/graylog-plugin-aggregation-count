package com.airbus_cyber_security.graylog.events.processor.aggregation.checks;

import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;

public interface Check {
    Result run(TimeRange range);
}