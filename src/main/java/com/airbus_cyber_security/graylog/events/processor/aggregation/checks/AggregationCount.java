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
                + configuration.thresholdType().toLowerCase(Locale.ENGLISH) + " than "
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
