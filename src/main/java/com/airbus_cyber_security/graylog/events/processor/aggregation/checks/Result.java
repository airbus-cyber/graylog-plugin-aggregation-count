package com.airbus_cyber_security.graylog.events.processor.aggregation.checks;

import org.graylog2.plugin.MessageSummary;

import java.util.List;

public class Result {

    private String resultDescription;

    private List<MessageSummary> messageSummaries;

    public Result(final String resultDescription, final List<MessageSummary> messageSummaries) {
        this.resultDescription = resultDescription;
        this.messageSummaries = messageSummaries;
    }

    public String getResultDescription() {
        return resultDescription;
    }

    public List<MessageSummary> getMessageSummaries() {
        return messageSummaries;
    }
}
