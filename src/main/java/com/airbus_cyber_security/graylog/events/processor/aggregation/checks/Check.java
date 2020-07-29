package com.airbus_cyber_security.graylog.events.processor.aggregation.checks;

import com.airbus_cyber_security.graylog.events.processor.aggregation.AggregationCountCheckResult;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;

public interface Check {
    AggregationCountCheckResult run(TimeRange range);
}