package com.airbus_cyber_security.graylog.events.processor.aggregation.checks;

import com.airbus_cyber_security.graylog.events.processor.aggregation.AggregationCountCheckResult;
import com.airbus_cyber_security.graylog.events.processor.aggregation.AggregationCountProcessorConfig;
import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.results.CountResult;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;

public class NoFields implements Check {

    private final MoreSearch moreSearch;
    private final String resultDescriptionPattern;
    private final int searchLimit;
    private final AggregationCountProcessorConfig configuration;

    public NoFields(AggregationCountProcessorConfig configuration, MoreSearch moreSearch, String resultDescriptionPattern, int searchLimit) {
        this.moreSearch = moreSearch;
        this.resultDescriptionPattern = resultDescriptionPattern;
        this.searchLimit = searchLimit;
        this.configuration = configuration;
    }

    private String buildQueryFilter(String streamId, String query) {
        Preconditions.checkArgument(streamId != null, "streamId parameter cannot be null");
        String trimmedStreamId = streamId.trim();
        Preconditions.checkArgument(!trimmedStreamId.isEmpty(), "streamId parameter cannot be empty");
        StringBuilder builder = (new StringBuilder()).append("streams:").append(trimmedStreamId);
        if (query != null) {
            String trimmedQuery = query.trim();
            if (!trimmedQuery.isEmpty() && !"*".equals(trimmedQuery)) {
                builder.append(" AND (").append(trimmedQuery).append(")");
            }
        }

        return builder.toString();
    }

    public AggregationCountCheckResult run(TimeRange range) {
        String filter = buildQueryFilter(this.configuration.stream(), this.configuration.searchQuery());
        CountResult result = this.moreSearch.count("*", range, filter);
        long count = result.count();
        boolean triggered;
        switch (ThresholdType.fromString(this.configuration.thresholdType())) {
            case MORE:
                triggered = count > (long) this.configuration.threshold();
                break;
            case LESS:
                triggered = count < (long) this.configuration.threshold();
                break;
            default:
                triggered = false;
        }

        if (!triggered) {
            return new AggregationCountCheckResult("", new ArrayList<>());
        }
        List<MessageSummary> summaries = Lists.newArrayList();
        SearchResult backlogResult = this.moreSearch.search("*", filter, range, this.searchLimit, 0, new Sorting("timestamp", Sorting.Direction.DESC));

        for (ResultMessage resultMessage: backlogResult.getResults()) {
            Message msg = resultMessage.getMessage();
            summaries.add(new MessageSummary(resultMessage.getIndex(), msg));
        }
        String resultDescription = MessageFormat.format(this.resultDescriptionPattern, count);
        return new AggregationCountCheckResult(resultDescription, summaries);
    }
}
