package com.airbus_cyber_security.graylog;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.graylog2.Configuration;
import org.graylog2.indexer.results.TermsResult;
import org.graylog2.indexer.searches.Sorting.Direction;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.junit.Test;
import org.mockito.Mock;

public class AggregationCountAggregateTest extends AlertConditionTest{
    @Mock
    protected Configuration configuration;
   
    private final int threshold = 100;
    
    @Test
    public void testRunCheckWithAggregateMorePositive() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.MORE;

        List<String> aggregatingFields = new ArrayList<>();
        aggregatingFields.add("user");
        aggregatingFields.add("ip_src");

        List<String> differentiatingFields = new ArrayList<>();

        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold, aggregatingFields, differentiatingFields, 100);

        searchTermsThreeAggregateShouldReturn(threshold + 1L);
        searchResultShouldReturn();
        // AlertCondition was never triggered before
        final AlertCondition.CheckResult result = aggregationCount.runCheck();

        assertTriggered(aggregationCount, result);
        assertEquals("Matching messages ", 3, result.getMatchingMessages().size());
    }

    @Test
    public void testRunCheckWithAggregateLessPositive() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.LESS;

        List<String> aggregatingFields = new ArrayList<>();
        aggregatingFields.add("user");
        aggregatingFields.add("ip_src");
        
        List<String> differentiatingFields = new ArrayList<>();
        differentiatingFields.add("user");
        
        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold, aggregatingFields, differentiatingFields, 100);

        searchTermsOneAggregateShouldReturn(threshold + 1L);
        searchResultShouldReturn();

        final AlertCondition.CheckResult result = aggregationCount.runCheck();

        assertTriggered(aggregationCount, result);
        assertEquals("Matching messages ", 1, result.getMatchingMessages().size());
    }

    @Test
    public void testRunCheckWithAggregateMoreNegative() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.MORE;
        
        List<String> aggregatingFields = new ArrayList<>();
        aggregatingFields.add("user");
        List<String> differentiatingFields = new ArrayList<>();
        differentiatingFields.add("user");

        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold, aggregatingFields, differentiatingFields, 100);

        searchTermsOneAggregateShouldReturn(threshold - 1L);
        searchResultShouldReturn();

        final AlertCondition.CheckResult result = aggregationCount.runCheck();

        assertNotTriggered(result);
    }

    @Test
    public void testRunCheckWithAggregateLessNegative() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.LESS;
        
        List<String> aggregatingFields = new ArrayList<>();
        aggregatingFields.add("user");
        
        List<String> differentiatingFields = new ArrayList<>();

        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold, aggregatingFields, differentiatingFields, 100);

        searchTermsThreeAggregateShouldReturn(threshold +1L);
        searchResultShouldReturn();
        
        final AlertCondition.CheckResult result = aggregationCount.runCheck();

        assertNotTriggered(result);
    }

    @Test
    public void testRunCheckWithAggregateMorePositiveWithNoBacklog() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.MORE;

        List<String> aggregatingFields = new ArrayList<>();
        aggregatingFields.add("user");
        aggregatingFields.add("ip_src");

        List<String> differentiatingFields = new ArrayList<>();

        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold, aggregatingFields, differentiatingFields, 0);

        searchTermsThreeAggregateShouldReturn(threshold + 1L);
        searchResultShouldReturn();
        // AlertCondition was never triggered before
        final AlertCondition.CheckResult result = aggregationCount.runCheck();

        assertTriggered(aggregationCount, result);
        assertEquals("Matching messages ", 0, result.getMatchingMessages().size());
    }
    
    protected void searchTermsOneAggregateShouldReturn(long count) {
        final TermsResult termsResult = mock(TermsResult.class);   
        Map<String, Long> terms = new HashMap<String, Long>();
        terms.put("user - ip1", count);

        when(termsResult.getTerms()).thenReturn(terms);

		when(searches.terms(anyString(), anyList() , any(int.class), anyString(), anyString(), any(TimeRange.class), any(Direction .class))).thenReturn(termsResult);
		
    }
    
    protected void searchTermsThreeAggregateShouldReturn(long count) {
        final TermsResult termsResult = mock(TermsResult.class);   
        Map<String, Long> terms = new HashMap<String, Long>();
        terms.put("user - ip1", count);
        terms.put("user - ip2", count);
        terms.put("user - ip3", count);

        when(termsResult.getTerms()).thenReturn(terms);

		when(searches.terms(anyString(), anyList() , any(int.class), anyString(), anyString(), any(TimeRange.class), any(Direction .class))).thenReturn(termsResult);
    }

    private AggregationCount getConditionWithParameters(AggregationCount.ThresholdType type, Integer threshold, List<String> fields, List<String> differentiatingFields, int backlog) {
        Map<String, Object> parameters = simplestParameterMap(type, threshold, fields, differentiatingFields, backlog);
        return getAggregationCount(parameters, alertConditionTitle);
    }
    
    private Map<String, Object> simplestParameterMap(AggregationCount.ThresholdType type, Integer threshold, List<String> fields, List<String> differentiatingFields, int backlog) {
        return getParametersMap(0, 0, type, threshold, fields, differentiatingFields, backlog);
    }



}
