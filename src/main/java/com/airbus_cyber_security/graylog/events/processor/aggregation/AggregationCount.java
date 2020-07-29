package com.airbus_cyber_security.graylog.events.processor.aggregation;

import com.airbus_cyber_security.graylog.events.processor.aggregation.checks.NoFields;
import com.airbus_cyber_security.graylog.events.processor.aggregation.checks.ThresholdType;
import com.google.common.collect.Lists;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.results.TermsResult;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.MessageFormat;
import java.util.*;

public class AggregationCount {
    private static final Logger LOG = LoggerFactory.getLogger(AggregationCount.class);
    private static final int SEARCH_LIMIT = 500;

    private String thresholdType;
    private int threshold;
    private String aggregatesThresholdType;
    private int aggregatesThreshold;
    private final MoreSearch moreSearch;
    private final AggregationCountProcessorConfig configuration;
    private final String resultDescriptionPattern;
    private final NoFields check;

    public AggregationCount(MoreSearch moreSearch, AggregationCountProcessorConfig configuration) {
        this.moreSearch = moreSearch;
        setThresholds(configuration);
        this.resultDescriptionPattern = buildResultDescriptionPattern(configuration);
        this.configuration = configuration;
        this.check = new NoFields(configuration, moreSearch, resultDescriptionPattern, SEARCH_LIMIT);
    }

    private boolean isTriggered(ThresholdType thresholdType, int threshold, long count) {
        return (((thresholdType == ThresholdType.MORE) && (count > threshold)) ||
                ((thresholdType == ThresholdType.LESS) && (count < threshold)));
    }

    private void addSearchMessages(List<MessageSummary> summaries, String searchQuery, String filter, TimeRange range) {
        final SearchResult backlogResult = this.moreSearch.search(searchQuery, filter,
                range, SEARCH_LIMIT, 0, new Sorting(Message.FIELD_TIMESTAMP, Sorting.Direction.DESC));
        for (ResultMessage resultMessage: backlogResult.getResults()) {
            if (summaries.size() >= SEARCH_LIMIT) {
                break;
            }
            summaries.add(new MessageSummary(resultMessage.getIndex(), resultMessage.getMessage()));
        }
    }

    private String buildSearchQuery(String firstField, List<String> nextFields, String matchedFieldValue) {
        matchedFieldValue = matchedFieldValue.replaceAll("\\\\", "\\\\\\\\");
        for (String field : nextFields) {
            matchedFieldValue = matchedFieldValue.replaceFirst(" - ", "\" AND " + field + ": \"");
        }
        return (this.configuration.searchQuery() + " AND " + firstField + ": \"" + matchedFieldValue + "\"");
    }

    private String getResultDescription(long messagesNumber) {
        return MessageFormat.format(this.resultDescriptionPattern, messagesNumber);
    }

    private boolean getListMessageSummary(List<MessageSummary> summaries, Map<String, List<String>> matchedTerms,
                                          String firstField, List<String> nextFields, TimeRange range, String filter) {
        Boolean ruleTriggered = false;
        Map<String, Long> frequenciesFields = new HashMap<>();
        for (Map.Entry<String, List<String>> matchedTerm: matchedTerms.entrySet()) {
            String valuesAgregates = matchedTerm.getKey();
            List<String> listAggregates = matchedTerm.getValue();

            if (!frequenciesFields.containsKey(valuesAgregates)) {
                frequenciesFields.put(valuesAgregates, (long) listAggregates.size());
                LOG.debug(listAggregates.size() + " aggregates for values " + valuesAgregates);
            }
        }

        for (Map.Entry<String, Long> frequencyField: frequenciesFields.entrySet()) {
            if (isTriggered(ThresholdType.fromString(aggregatesThresholdType), aggregatesThreshold, frequencyField.getValue())) {
                ruleTriggered = true;

                for (String matchedFieldValue: matchedTerms.get(frequencyField.getKey())) {
                    String searchQuery = buildSearchQuery(firstField, nextFields, matchedFieldValue);

                    LOG.debug("Search: " + searchQuery);

                    addSearchMessages(summaries, searchQuery, filter, range);

                    LOG.debug(summaries.size() + " Messages in CheckResult");
                }
            }
        }
        return ruleTriggered;
    }

    /**
     * @param matchedTerms non-null list of matched terms to return
     * @param termsResult
     * @return return the rule count
     **/
    private long getMatchedTerm(Map<String, List<String>> matchedTerms, TermsResult termsResult) {
        long ruleCount = 0;
        boolean isFirstTriggered = true;
        for (Map.Entry<String, Long> term: termsResult.getTerms().entrySet()) {

            String matchedFieldValue = term.getKey();
            Long count = term.getValue();

            if (isTriggered(ThresholdType.fromString(thresholdType), threshold, count)) {
                String [] valuesFields = matchedFieldValue.split(" - ");
                int i=0;
                StringBuilder bldStringValuesAgregates = new StringBuilder("Agregates:");
                for (String field: getFields()) {
                    if (this.configuration.groupingFields().contains(field) && i < valuesFields.length) {
                        bldStringValuesAgregates.append(valuesFields[i]);
                    }
                    i++;
                }
                String valuesAgregates = bldStringValuesAgregates.toString();

                if(matchedTerms.containsKey(valuesAgregates)) {
                    matchedTerms.get(valuesAgregates).add(matchedFieldValue);
                } else {
                    matchedTerms.put(valuesAgregates, Lists.newArrayList(matchedFieldValue));
                }

                if(isFirstTriggered) {
                    ruleCount = count;
                    isFirstTriggered = false;
                }
            }
        }
        return ruleCount;
    }

    /**
     * Check if the condition is triggered
     *
     * This condition is triggered when the number of messages with the same value of some message fields
     * and with distinct values of other messages fields is higher/lower than a defined threshold in a given time range.
     *
     * @return AggregationCountCheckResult
     * 					Result Description and list of messages that satisfy the conditions
     */
    public AggregationCountCheckResult runCheckAggregationField(TimeRange range) {
        final String filter = "streams:" + this.configuration.stream();
        String firstField = getFields().iterator().next();
        List<String> nextFields = new ArrayList<>(getFields());
        nextFields.remove(0);

        /* Get the matched term */
        TermsResult result = this.moreSearch.terms(firstField, nextFields, SEARCH_LIMIT, this.configuration.searchQuery(), filter, range, Sorting.Direction.DESC);
        Map<String, List<String>> matchedTerms = new HashMap<>();
        long  ruleCount = getMatchedTerm(matchedTerms, result);

        /* Get the list of summary messages */
        List<MessageSummary> summaries = Lists.newArrayListWithCapacity(SEARCH_LIMIT);
        boolean ruleTriggered = getListMessageSummary(summaries, matchedTerms, firstField, nextFields, range, filter);

        /* If rule triggered return the check result */
        if (ruleTriggered) {
            long messageNumber;
            if (!configuration.distinctionFields().isEmpty()) {
                messageNumber = summaries.size();
            } else {
                messageNumber = ruleCount;
            }
            String resultDescription = this.getResultDescription(messageNumber);
            return new AggregationCountCheckResult(resultDescription, summaries);
        }

        return new AggregationCountCheckResult("", new ArrayList<>());
    }

    public AggregationCountCheckResult runCheck(TimeRange timerange) {
        boolean hasFields = !(this.configuration.groupingFields().isEmpty() && this.configuration.distinctionFields().isEmpty());
        if (hasFields) {
            return this.runCheckAggregationField(timerange);
        } else {
            return this.check.run(timerange);
        }
    }

    private List<String> getFields() {
        List<String> fields = new ArrayList<>();
        if (!this.configuration.groupingFields().isEmpty()) {
            fields.addAll(this.configuration.groupingFields());
        }
        if (!this.configuration.distinctionFields().isEmpty()) {
            fields.addAll(this.configuration.distinctionFields());
        }
        return fields;
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

    private void setThresholds(AggregationCountProcessorConfig configuration) {
        if (!configuration.distinctionFields().isEmpty()) {
            this.thresholdType = ThresholdType.MORE.getDescription();
            this.threshold = 0;
            this.aggregatesThresholdType = configuration.thresholdType();
            this.aggregatesThreshold = configuration.threshold();
        } else {
            this.thresholdType = configuration.thresholdType();
            this.threshold = configuration.threshold();
            this.aggregatesThresholdType = ThresholdType.MORE.getDescription();
            this.aggregatesThreshold = 0;
        }
    }
}
