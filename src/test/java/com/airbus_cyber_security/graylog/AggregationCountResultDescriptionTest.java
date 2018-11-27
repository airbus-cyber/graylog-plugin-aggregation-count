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
import org.graylog2.indexer.results.CountResult;
import org.graylog2.indexer.results.TermsResult;
import org.graylog2.indexer.searches.Sorting.Direction;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.indexer.searches.timeranges.TimeRange;
import org.junit.Test;
import org.mockito.Mock;

import com.airbus_cyber_security.graylog.AggregationCount;

public class AggregationCountResultDescriptionTest extends AlertConditionTest{
    @Mock
    protected Configuration configuration;
   
    private final int threshold = 9;
    
    @Test
    public void testRunCheckWithGroupingFieldsAndDistinctFields() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.LESS;

        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("src");
        groupingFields.add("dst");
        
        List<String> distinctionFields = new ArrayList<>();
        distinctionFields.add("dest_port");
        
        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold, groupingFields, distinctionFields, 100);
        
        searchTermsOneAggregateShouldReturn(threshold + 1L);
        searchResultShouldReturn();
        final AlertCondition.CheckResult result = aggregationCount.runCheck();
        
        assertTriggered(aggregationCount, result);
        
        String resultDescription = "Stream had 1 messages in the last 0 minutes with trigger condition less than 9 messages "
        		+ "with the same value of the fields src, dst, and with distinct values of the fields dest_port. (Current grace time: 0 minutes)";
        assertEquals("ResultDescription", resultDescription, result.getResultDescription());
    }
    
    
    @Test
    public void testRunCheckWithGroupingFieldsAndNoDistinctFields() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.LESS;

        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("src");
        groupingFields.add("dst");
        
        List<String> distinctionFields = new ArrayList<>();
        
        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold, groupingFields, distinctionFields, 100);
        
        searchTermsOneAggregateShouldReturn(threshold - 1L);
        searchResultShouldReturn();
        final AlertCondition.CheckResult result = aggregationCount.runCheck();
        
        assertTriggered(aggregationCount, result);
        
        String resultDescription = "Stream had 8 messages in the last 0 minutes with trigger condition less than 9 messages "
        		+ "with the same value of the fields src, dst. (Current grace time: 0 minutes)";
        assertEquals("ResultDescription", resultDescription, result.getResultDescription());
    }
    
    @Test
    public void testRunCheckWithNoGroupingFieldsAndDistinctFields() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.LESS;

        List<String> groupingFields = new ArrayList<>();
        
        List<String> distinctionFields = new ArrayList<>();
        distinctionFields.add("dest_port");
        
        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold, groupingFields, distinctionFields, 100);
        
        searchTermsOneAggregateShouldReturn(threshold + 1L);
        searchResultShouldReturn();
        final AlertCondition.CheckResult result = aggregationCount.runCheck();
        
        assertTriggered(aggregationCount, result);
        
        String resultDescription = "Stream had 1 messages in the last 0 minutes with trigger condition less than 9 messages "
		+ "with distinct values of the fields dest_port. (Current grace time: 0 minutes)";
        assertEquals("ResultDescription", resultDescription, result.getResultDescription());
    }
    
    @Test
    public void testRunCheckWithNoGroupingFieldsAndNoDistinctFields() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.MORE;

        List<String> groupingFields = new ArrayList<>();    
        List<String> distinctionFields = new ArrayList<>();
        
        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold, groupingFields, distinctionFields, 0);
         
        searchCountShouldReturn(threshold + 1L);
        final AlertCondition.CheckResult result = aggregationCount.runCheck();
        
        String resultDescription = "Stream had 10 messages in the last 0 minutes with trigger condition more than 9 messages. (Current grace time: 0 minutes)";
        assertEquals("ResultDescription", resultDescription, result.getResultDescription());
    }
    
    private void searchCountShouldReturn(long count) {
        final CountResult countResult = mock(CountResult.class);
        when(countResult.count()).thenReturn(count);

        when(searches.count(anyString(), any(TimeRange.class), anyString())).thenReturn(countResult);
    }
    
    protected void searchTermsOneAggregateShouldReturn(long count) {
        final TermsResult termsResult = mock(TermsResult.class);   
        Map<String, Long> terms = new HashMap<String, Long>();
        terms.put("src - ip1", count);

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
