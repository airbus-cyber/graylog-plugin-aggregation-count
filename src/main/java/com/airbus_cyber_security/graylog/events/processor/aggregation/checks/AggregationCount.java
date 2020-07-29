package com.airbus_cyber_security.graylog.events.processor.aggregation.checks;

import com.airbus_cyber_security.graylog.events.processor.aggregation.AggregationCountProcessorConfig;
import org.graylog.events.search.MoreSearch;

import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;

import java.util.Locale;

public class AggregationCount {
    private static final int SEARCH_LIMIT = 500;

    private final Check check;

    public AggregationCount(MoreSearch moreSearch, AggregationCountProcessorConfig configuration) {
        String resultDescriptionPattern = buildResultDescriptionPattern(configuration);
        Result.Builder resultBuilder = new Result.Builder(resultDescriptionPattern);
        boolean hasFields = !(configuration.groupingFields().isEmpty() && configuration.distinctionFields().isEmpty());
        if (hasFields) {
            this.check = new AggregationField(configuration, moreSearch, SEARCH_LIMIT, resultBuilder);
        } else {
            this.check = new NoFields(configuration, moreSearch, SEARCH_LIMIT, resultBuilder);
        }
    }

    public Result runCheck(TimeRange timerange) {
        return this.check.run(timerange);
    }

    private String buildResultDescriptionPattern(AggregationCountProcessorConfig configuration) {

        String result = "Stream had {0} messages in the last "
                + configuration.searchWithinMs() + " milliseconds with trigger condition "
                + configuration.thresholdType().toLowerCase(Locale.ENGLISH) + " "
                + configuration.threshold() + " messages";

        if (!configuration.groupingFields().isEmpty()) {
            result += " with the same value of the fields " + String.join(", ",configuration.groupingFields());
        }

        if (!configuration.groupingFields().isEmpty() && !configuration.distinctionFields().isEmpty()) {
            result += ", and";
        }

        if (!configuration.distinctionFields().isEmpty()) {
            result += " with distinct values of the fields " + String.join(", ",configuration.distinctionFields());
        }

        result += ". (Executes every: " + configuration.executeEveryMs() + " milliseconds)";

        return result;
    }
}
