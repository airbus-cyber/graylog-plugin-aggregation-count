package com.airbus_cyber_security.graylog;

import org.graylog2.plugin.MessageSummary;

import java.util.List;

public class AggregationCountCheckResult {

    private String resultDescription;

    private List<MessageSummary> messageSummaries;

    public AggregationCountCheckResult(final String resultDescription, final List<MessageSummary> messageSummaries) {
        this.resultDescription = resultDescription;
        this.messageSummaries = messageSummaries;
    }

    public String getResultDescription() {
        return resultDescription;
    }

    public void setResultDescription(String resultDescription) {
        this.resultDescription = resultDescription;
    }

    public List<MessageSummary> getMessageSummaries() {
        return messageSummaries;
    }

    public void setMessageSummaries(List<MessageSummary> messageSummaries) {
        this.messageSummaries = messageSummaries;
    }
}
