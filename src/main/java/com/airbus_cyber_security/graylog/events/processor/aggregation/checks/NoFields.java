/*
 * graylog-plugin-aggregation-count Source Code
 * Copyright (C) 2018-2020 - Airbus CyberSecurity (SAS) - All rights reserved
 *
 * This file is part of the graylog-plugin-aggregation-count GPL Source Code.
 *
 * graylog-plugin-aggregation-count Source Code is free software:
 * you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this code.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.airbus_cyber_security.graylog.events.processor.aggregation.checks;

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

import java.util.List;

public class NoFields implements Check {

    private final AggregationCountProcessorConfig configuration;
    private final MoreSearch moreSearch;
    private final int searchLimit;
    private final Result.Builder resultBuilder;

    public NoFields(AggregationCountProcessorConfig configuration, MoreSearch moreSearch, int searchLimit, Result.Builder resultBuilder) {
        this.configuration = configuration;
        this.moreSearch = moreSearch;
        this.searchLimit = searchLimit;
        this.resultBuilder = resultBuilder;
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

    public Result run(TimeRange range) {
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
            return this.resultBuilder.buildEmpty();
        }
        List<MessageSummary> summaries = Lists.newArrayList();
        SearchResult backlogResult = this.moreSearch.search("*", filter, range, this.searchLimit, 0, new Sorting("timestamp", Sorting.Direction.DESC));

        for (ResultMessage resultMessage: backlogResult.getResults()) {
            Message msg = resultMessage.getMessage();
            summaries.add(new MessageSummary(resultMessage.getIndex(), msg));
        }
        return this.resultBuilder.build(count, summaries);
    }
}
