package com.airbus_cyber_security.graylog.events.processor.aggregation;

import com.google.common.collect.Lists;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.results.CountResult;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.results.TermsResult;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AggregationCountTest {

    private final int threshold = 100;

    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();

    @Mock
    private MoreSearch moreSearch;

    private AggregationCount subject;

    @Test
    public void runCheckWithAggregateMorePositive() {
        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        groupingFields.add("ip_src");
        List<String> distinctionFields = new ArrayList<>();
        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(AggregationCount.ThresholdType.MORE, threshold, groupingFields, distinctionFields, 100);
        this.subject = new AggregationCount(this.moreSearch, configuration);

        searchTermsThreeAggregateWillReturn(threshold + 1L);
        when(moreSearch.search(anyString(), anyString(), any(TimeRange.class), any(int.class), any(int.class), any(Sorting.class))).thenReturn(buildDummySearchResult());
        AggregationCountCheckResult result = this.subject.runCheck(buildDummyTimeRange());

        String resultDescription = "Stream had " + (threshold+1) + " messages in the last 0 milliseconds with trigger condition more "
                + configuration.threshold() + " messages with the same value of the fields " + String.join(", ", configuration.groupingFields())
                + ". (Executes every: 0 milliseconds)";
        assertEquals(resultDescription, result.getResultDescription());
        assertEquals("Matching messages ", 3, result.getMessageSummaries().size());
    }

    @Test
    public void runCheckWithAggregateLessPositive() {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.LESS;
        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        groupingFields.add("ip_src");
        List<String> distinctionFields = new ArrayList<>();
        distinctionFields.add("user");
        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields, 100);
        this.subject = new AggregationCount(this.moreSearch, configuration);

        searchTermsOneAggregateShouldReturn(threshold + 1L);
        when(moreSearch.search(anyString(), anyString(), any(TimeRange.class), any(int.class), any(int.class), any(Sorting.class))).thenReturn(buildDummySearchResult());

        AggregationCountCheckResult result = this.subject.runCheck(buildDummyTimeRange());

        String resultDescription = "Stream had 1 messages in the last 0 milliseconds with trigger condition less "
                + configuration.threshold() + " messages with the same value of the fields " + String.join(", ", configuration.groupingFields())
                + ", and with distinct values of the fields " + String.join(", ", configuration.distinctionFields()) + ". (Executes every: 0 milliseconds)";
        assertEquals(resultDescription, result.getResultDescription());
        assertEquals("Matching messages ", 1, result.getMessageSummaries().size());
    }

    @Test
    public void runCheckWithAggregateMoreNegative() {
        AggregationCount.ThresholdType type = AggregationCount.ThresholdType.MORE;
        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        List<String> distinctionFields = new ArrayList<>();
        distinctionFields.add("user");
        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields, 100);
        this.subject = new AggregationCount(this.moreSearch, configuration);

        searchTermsOneAggregateShouldReturn(threshold - 1L);

        AggregationCountCheckResult result = this.subject.runCheck(buildDummyTimeRange());
        assertEquals("", result.getResultDescription());
        assertEquals("Matching messages ", 0, result.getMessageSummaries().size());
    }

    @Test
    public void runCheckWithAggregateLessNegative() {
        AggregationCount.ThresholdType type = AggregationCount.ThresholdType.LESS;
        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        List<String> distinctionFields = new ArrayList<>();
        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields, 100);
        this.subject = new AggregationCount(this.moreSearch, configuration);

        searchTermsThreeAggregateWillReturn(threshold +1L);

        AggregationCountCheckResult result = this.subject.runCheck(buildDummyTimeRange());
        assertEquals("", result.getResultDescription());
        assertEquals("Matching messages ", 0, result.getMessageSummaries().size());
    }

    @Test
    public void runCheckWithAggregateMorePositiveWithNoBacklog() {
        AggregationCount.ThresholdType type = AggregationCount.ThresholdType.MORE;
        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        groupingFields.add("ip_src");
        List<String> distinctionFields = new ArrayList<>();
        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields, 0);
        this.subject = new AggregationCount(this.moreSearch, configuration);

        searchTermsThreeAggregateWillReturn(threshold + 1L);
        when(moreSearch.search(anyString(), anyString(), any(TimeRange.class), any(int.class), any(int.class), any(Sorting.class))).thenReturn(buildDummySearchResult());

        AggregationCountCheckResult result = this.subject.runCheck(buildDummyTimeRange());
        String resultDescription = "Stream had " + (threshold+1) + " messages in the last 0 milliseconds with trigger condition more "
                + configuration.threshold() + " messages with the same value of the fields " + String.join(", ", configuration.groupingFields())
                + ". (Executes every: 0 milliseconds)";
        assertEquals(resultDescription, result.getResultDescription());
        assertEquals("Matching messages ", 3, result.getMessageSummaries().size());
    }

    @Test
    public void runCheckWithNoGroupingFieldsAndNoDistinctFields() {
        AggregationCount.ThresholdType type = AggregationCount.ThresholdType.MORE;
        List<String> groupingFields = new ArrayList<>();
        List<String> distinctionFields = new ArrayList<>();
        final int thresholdTest = 9;

        AggregationCountProcessorConfig configuration = getAggregationCountProcessorConfigWithFields(type, thresholdTest, groupingFields, distinctionFields, 0);
        this.subject = new AggregationCount(this.moreSearch, configuration);

        final CountResult countResult = mock(CountResult.class);
        when(countResult.count()).thenReturn(thresholdTest + 1L);
        when(moreSearch.count(anyString(), any(TimeRange.class), anyString())).thenReturn(countResult);
        when(moreSearch.search(anyString(), anyString(), any(TimeRange.class), any(int.class), any(int.class), any(Sorting.class))).thenReturn(buildDummySearchResult());

        AggregationCountCheckResult result = this.subject.runCheck(buildDummyTimeRange());

        String resultDescription = "Stream had 10 messages in the last 0 milliseconds with trigger condition more 9 messages. (Executes every: 0 milliseconds)";
        assertEquals("ResultDescription", resultDescription, result.getResultDescription());
    }

    private AggregationCountProcessorConfig getAggregationCountProcessorConfigWithFields(AggregationCount.ThresholdType type,
                                                                                         int threshold, List<String> groupingFields, List<String> distinctionFields, int backlog) {
        return AggregationCountProcessorConfig.builder()
                .stream("main stream")
                .thresholdType(type.getDescription())
                .threshold(threshold)
                .searchWithinMs(0)
                .executeEveryMs(0)
                .messageBacklog(backlog)
                .groupingFields(new HashSet<>(groupingFields))
                .distinctionFields(new HashSet<>(distinctionFields))
                .comment("test comment")
                .searchQuery("*")
                .repeatNotifications(false)
                .build();
    }

    private void searchTermsOneAggregateShouldReturn(long count) {
        final TermsResult termsResult = mock(TermsResult.class);
        Map<String, Long> terms = new HashMap<String, Long>();
        terms.put("user - ip1", count);

        when(termsResult.getTerms()).thenReturn(terms);

        when(moreSearch.terms(anyString(), anyList() , any(int.class), anyString(), anyString(), any(TimeRange.class), any(Sorting.Direction.class))).thenReturn(termsResult);

    }

    private void searchTermsThreeAggregateWillReturn(long count) {
        final TermsResult termsResult = mock(TermsResult.class);
        Map<String, Long> terms = new HashMap<String, Long>();
        terms.put("user - ip1", count);
        terms.put("user - ip2", count);
        terms.put("user - ip3", count);

        when(termsResult.getTerms()).thenReturn(terms);

        when(moreSearch.terms(anyString(), anyList() , any(int.class), anyString(), anyString(), any(TimeRange.class), any(Sorting.Direction.class))).thenReturn(termsResult);
    }

    private SearchResult buildDummySearchResult() {
        List<ResultMessage> hits = Lists.newArrayList(
                ResultMessage.parseFromSource("id", "index", new HashMap<String, Object>())
        );
        return new SearchResult(hits, 2, new HashSet<>(), "originalQuery", "builtQuery", 0);
    }

    private TimeRange buildDummyTimeRange() {
        DateTime now = DateTime.now(DateTimeZone.UTC);
        return AbsoluteRange.create(now.minusHours(1), now.plusHours(1));
    }
}
