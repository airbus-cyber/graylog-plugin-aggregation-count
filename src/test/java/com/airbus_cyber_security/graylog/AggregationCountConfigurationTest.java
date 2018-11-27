package com.airbus_cyber_security.graylog;

import static org.junit.Assert.assertEquals;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.junit.Test;

import com.airbus_cyber_security.graylog.AggregationCount;
import com.airbus_cyber_security.graylog.AggregationCount.ThresholdType;

public class AggregationCountConfigurationTest extends AlertConditionTest {
     
    public String buildDescription(int grace, int time, ThresholdType thresholdType, int threshold, List<String> fields, 
    		ThresholdType aggregatesThresholdType, int aggregatesThreshold, List<String> aggregatesFields, boolean repeatNotifications) {
        return "time: " + time
                + ", threshold_type: " + thresholdType.toString().toLowerCase(Locale.ENGLISH)
                + ", threshold: " + threshold
                + ", grace: " + grace
                + ", fields: " + String.join(" ",fields)
                + ", aggregates_threshold_type: " + aggregatesThresholdType.toString().toLowerCase(Locale.ENGLISH)
                + ", aggregates_threshold: " + aggregatesThreshold
                + ", aggregates_fields: " + String.join(" ",aggregatesFields)
                + ", repeat notifications: " + repeatNotifications;
    }
    
    @Test
    public void testConfiguration1() throws Exception {
    	List<String> aggregatingFields = new ArrayList<>();
    	aggregatingFields.add("field_1");
        List<String> differentiatingFields = new ArrayList<>();
        differentiatingFields.add("field_2"); 
        final Map<String, Object> parameters = getParametersMap(0, 0, AggregationCount.ThresholdType.LESS, 5, aggregatingFields, differentiatingFields, 100);
        final AggregationCount aggregationCount = getAggregationCount(parameters, alertConditionTitle);

        List<String> fields = new ArrayList<>();
        fields.add("field_1");
        fields.add("field_2");
        List<String> aggregatesFields = new ArrayList<>();
        aggregatesFields.add("field_1");
        String description = buildDescription(0, 0, AggregationCount.ThresholdType.MORE, 0, fields, AggregationCount.ThresholdType.LESS, 5, aggregatesFields,false);

        assertEquals(description, aggregationCount.getDescription());
    }
    
    @Test
    public void testConfiguration2() throws Exception {
    	List<String> aggregatingFields = new ArrayList<>();
    	aggregatingFields.add("field_1");
        List<String> differentiatingFields = new ArrayList<>();
        final Map<String, Object> parameters = getParametersMap(0, 0, AggregationCount.ThresholdType.LESS, 5, aggregatingFields, differentiatingFields, 100);
        final AggregationCount aggregationCount = getAggregationCount(parameters, alertConditionTitle);

        List<String> fields = new ArrayList<>();
        fields.add("field_1");
        List<String> aggregatesFields = new ArrayList<>();
        aggregatesFields.add("field_1");
        String description = buildDescription(0, 0, AggregationCount.ThresholdType.LESS, 5, fields, AggregationCount.ThresholdType.MORE, 0, aggregatesFields,false);

        assertEquals(description, aggregationCount.getDescription());
    }
    
    @Test
    public void testConfiguration3() throws Exception {
    	List<String> aggregatingFields = new ArrayList<>();
        List<String> differentiatingFields = new ArrayList<>();
        differentiatingFields.add("field_2"); 
        final Map<String, Object> parameters = getParametersMap(0, 0, AggregationCount.ThresholdType.LESS, 5, aggregatingFields, differentiatingFields, 100);
        final AggregationCount aggregationCount = getAggregationCount(parameters, alertConditionTitle);

        List<String> fields = new ArrayList<>();
        fields.add("field_2");
        List<String> aggregatesFields = new ArrayList<>();
        String description = buildDescription(0, 0, AggregationCount.ThresholdType.MORE, 0, fields, AggregationCount.ThresholdType.LESS, 5, aggregatesFields,false);

        assertEquals(description, aggregationCount.getDescription());
    }
    
    @Test
    public void testConfiguration4() throws Exception {
    	List<String> aggregatingFields = new ArrayList<>();
        List<String> differentiatingFields = new ArrayList<>();
        final Map<String, Object> parameters = getParametersMap(0, 0, AggregationCount.ThresholdType.LESS, 5, aggregatingFields, differentiatingFields, 100);
        final AggregationCount aggregationCount = getAggregationCount(parameters, alertConditionTitle);

        List<String> fields = new ArrayList<>();
        List<String> aggregatesFields = new ArrayList<>();
        String description = buildDescription(0, 0, AggregationCount.ThresholdType.LESS, 5, fields, AggregationCount.ThresholdType.MORE, 0, aggregatesFields,false);

        assertEquals(description, aggregationCount.getDescription());
    }
}
