package com.airbus_cyber_security.graylog.events.processor.aggregation;

import com.google.common.collect.Lists;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.results.CountResult;
import org.graylog2.indexer.results.ResultMessage;
import org.graylog2.indexer.results.SearchResult;
import org.graylog2.indexer.results.TermsResult;
import org.graylog2.indexer.searches.Sorting;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
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


    @Test
    public void testRunCheckWithAggregateMorePositive() {
        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        groupingFields.add("ip_src");

        List<String> distinctionFields = new ArrayList<>();

        AggregationCountProcessorConfig config = getAggregationCountProcessorConfigWithFields(AggregationCount.ThresholdType.MORE, threshold, groupingFields, distinctionFields, 100);

        searchTermsThreeAggregateShouldReturn(threshold + 1L);
        searchResultShouldReturn();
        AggregationCount aggregationCount = new AggregationCount(this.moreSearch, config);
        AggregationCountCheckResult result = aggregationCount.runCheck(config);

        String resultDescription = "Stream had " + (threshold+1) + " messages in the last 0 milliseconds with trigger condition more "
                + config.threshold() + " messages with the same value of the fields " + String.join(", ", config.groupingFields())
                + ". (Executes every: 0 milliseconds)";
        assertEquals(resultDescription, result.getResultDescription());
        assertEquals("Matching messages ", 3, result.getMessageSummaries().size());
    }

    @Test
    public void testRunCheckWithAggregateLessPositive() {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.LESS;

        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        groupingFields.add("ip_src");

        List<String> distinctionFields = new ArrayList<>();
        distinctionFields.add("user");

        AggregationCountProcessorConfig config = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields, 100);

        searchTermsOneAggregateShouldReturn(threshold + 1L);
        searchResultShouldReturn();

        AggregationCount aggregationCount = new AggregationCount(this.moreSearch, config);
        AggregationCountCheckResult result = aggregationCount.runCheck(config);

        String resultDescription = "Stream had 1 messages in the last 0 milliseconds with trigger condition less "
                + config.threshold() + " messages with the same value of the fields " + String.join(", ", config.groupingFields())
                + ", and with distinct values of the fields " + String.join(", ", config.distinctionFields()) + ". (Executes every: 0 milliseconds)";
        assertEquals(resultDescription, result.getResultDescription());
        assertEquals("Matching messages ", 1, result.getMessageSummaries().size());
    }

    @Test
    public void testRunCheckWithAggregateMoreNegative() {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.MORE;

        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        List<String> distinctionFields = new ArrayList<>();
        distinctionFields.add("user");

        AggregationCountProcessorConfig config = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields, 100);

        searchTermsOneAggregateShouldReturn(threshold - 1L);
        searchResultShouldReturn();

        AggregationCount aggregationCount = new AggregationCount(this.moreSearch, config);
        AggregationCountCheckResult result = aggregationCount.runCheck(config);
        assertEquals("", result.getResultDescription());
        assertEquals("Matching messages ", 0, result.getMessageSummaries().size());
    }

    @Test
    public void testRunCheckWithAggregateLessNegative() {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.LESS;

        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");

        List<String> distinctionFields = new ArrayList<>();

        AggregationCountProcessorConfig config = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields, 100);

        searchTermsThreeAggregateShouldReturn(threshold +1L);
        searchResultShouldReturn();

        AggregationCount aggregationCount = new AggregationCount(this.moreSearch, config);
        AggregationCountCheckResult result = aggregationCount.runCheck(config);
        assertEquals("", result.getResultDescription());
        assertEquals("Matching messages ", 0, result.getMessageSummaries().size());
    }

    @Test
    public void testRunCheckWithAggregateMorePositiveWithNoBacklog() {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.MORE;

        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        groupingFields.add("ip_src");

        List<String> distinctionFields = new ArrayList<>();

        AggregationCountProcessorConfig config = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields, 0);

        searchTermsThreeAggregateShouldReturn(threshold + 1L);
        searchResultShouldReturn();
        AggregationCount aggregationCount = new AggregationCount(this.moreSearch, config);
        AggregationCountCheckResult result = aggregationCount.runCheck(config);
        String resultDescription = "Stream had " + (threshold+1) + " messages in the last 0 milliseconds with trigger condition more "
                + config.threshold() + " messages with the same value of the fields " + String.join(", ", config.groupingFields())
                + ". (Executes every: 0 milliseconds)";
        assertEquals(resultDescription, result.getResultDescription());
        assertEquals("Matching messages ", 0, result.getMessageSummaries().size());
    }

    @Test
    public void testRunCheckWithNoGroupingFieldsAndNoDistinctFields() {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.MORE;

        List<String> groupingFields = new ArrayList<>();
        List<String> distinctionFields = new ArrayList<>();
        final int thresholdTest = 9;

        AggregationCountProcessorConfig config = getAggregationCountProcessorConfigWithFields(type, thresholdTest, groupingFields, distinctionFields, 0);

        searchCountShouldReturn(thresholdTest + 1L);
        AggregationCount aggregationCount = new AggregationCount(this.moreSearch, config);
        AggregationCountCheckResult result = aggregationCount.runCheck(config);

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

    private void searchTermsThreeAggregateShouldReturn(long count) {
        final TermsResult termsResult = mock(TermsResult.class);
        Map<String, Long> terms = new HashMap<String, Long>();
        terms.put("user - ip1", count);
        terms.put("user - ip2", count);
        terms.put("user - ip3", count);

        when(termsResult.getTerms()).thenReturn(terms);

        when(moreSearch.terms(anyString(), anyList() , any(int.class), anyString(), anyString(), any(TimeRange.class), any(Sorting.Direction.class))).thenReturn(termsResult);
    }

    private void searchResultShouldReturn() {
        final SearchResult searchResult = mock(SearchResult.class);
        ResultMessage resultMessage = mock(ResultMessage.class);
        List <ResultMessage> listResultMessage = Lists.newArrayList(resultMessage);

        when(searchResult.getResults()).thenReturn(listResultMessage);

        when(moreSearch.search(anyString(), anyString(), any(TimeRange.class), any(int.class), any(int.class), any(Sorting.class))).thenReturn(searchResult);

    }

    private void searchCountShouldReturn(long count) {
        final CountResult countResult = mock(CountResult.class);
        when(countResult.count()).thenReturn(count);

        when(moreSearch.count(anyString(), any(TimeRange.class), anyString())).thenReturn(countResult);
    }
}
