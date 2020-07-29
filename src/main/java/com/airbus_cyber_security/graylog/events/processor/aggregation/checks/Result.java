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
