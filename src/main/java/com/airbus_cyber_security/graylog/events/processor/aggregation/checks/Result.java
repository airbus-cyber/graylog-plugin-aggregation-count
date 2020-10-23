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

import org.graylog2.plugin.MessageSummary;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;

public class Result {

    private final String resultDescription;

    private final List<MessageSummary> messageSummaries;

    private Result(final String resultDescription, final List<MessageSummary> messageSummaries) {
        this.resultDescription = resultDescription;
        this.messageSummaries = messageSummaries;
    }

    public String getResultDescription() {
        return resultDescription;
    }

    public List<MessageSummary> getMessageSummaries() {
        return messageSummaries;
    }

    public static class Builder {
        private final String resultDescriptionPattern;

        public Builder(String resultDescriptionPattern) {
            this.resultDescriptionPattern = resultDescriptionPattern;
        }

        public Result buildEmpty() {
            return new Result("", new ArrayList<>());
        }

        public Result build(long count, List<MessageSummary> summaries) {
            String resultDescription = MessageFormat.format(this.resultDescriptionPattern, count);
            return new Result(resultDescription, summaries);
        }
    }
}
