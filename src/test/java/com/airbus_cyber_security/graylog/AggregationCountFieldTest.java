package com.airbus_cyber_security.graylog;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.graylog2.Configuration;
import org.graylog2.plugin.alarms.AlertCondition;
import org.junit.Test;
import org.mockito.Mock;

import com.airbus_cyber_security.graylog.AggregationCount;
import com.airbus_cyber_security.graylog.AlertConditionTest;

public class AggregationCountFieldTest extends AlertConditionTest {
    @Mock
    protected Configuration configuration;
   
    private final int threshold = 100;

    @Test
    public void testConstructor() throws Exception {
        final Map<String, Object> parameters = getParametersMap(0, 0, AggregationCount.ThresholdType.MORE, 0);

        final AggregationCount aggregationCount = getAggregationCount(parameters, alertConditionTitle);

        assertNotNull(aggregationCount);
        assertNotNull(aggregationCount.getDescription());
        final String thresholdType = (String) aggregationCount.getParameters().get("threshold_type");
        assertEquals(thresholdType, thresholdType.toUpperCase(Locale.ENGLISH));
    }

    @Test
    public void testRunCheckWithFieldMorePositive() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.MORE;

        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold);

        searchTermsShouldReturn(threshold + 1);
        searchResultShouldReturn();
        // AlertCondition was never triggered before
        final AlertCondition.CheckResult result = aggregationCount.runCheck();

        assertTriggered(aggregationCount, result);
        assertEquals("Matching messages ", 2, result.getMatchingMessages().size());
    }

    @Test
    public void testRunCheckWithFieldLessPositive() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.LESS;

        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold);

        searchTermsShouldReturn(threshold - 1);
        searchResultShouldReturn();

        final AlertCondition.CheckResult result = aggregationCount.runCheck();

        assertTriggered(aggregationCount, result);
        assertEquals("Matching messages ", 2, result.getMatchingMessages().size());
    }

    @Test
    public void testRunCheckWithFieldMoreNegative() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.MORE;

        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold);

        searchTermsShouldReturn(threshold);

        final AlertCondition.CheckResult result = aggregationCount.runCheck();

        assertNotTriggered(result);
    }

    @Test
    public void testRunCheckWithFieldLessNegative() throws Exception {
        final AggregationCount.ThresholdType type = AggregationCount.ThresholdType.LESS;

        final AggregationCount aggregationCount = getConditionWithParameters(type, threshold);

        searchTermsShouldReturn(threshold);

        final AlertCondition.CheckResult result = aggregationCount.runCheck();

        assertNotTriggered(result);
    }

    private AggregationCount getConditionWithParameters(AggregationCount.ThresholdType type, Integer threshold) {
        Map<String, Object> parameters = simplestParameterMap(type, threshold);
        return getAggregationCount(parameters, alertConditionTitle);
    }

    private Map<String, Object> simplestParameterMap(AggregationCount.ThresholdType type, Integer threshold) {
        return getParametersMap(0, 0, type, threshold);
    }


    private Map<String, Object> getParametersMap(Integer grace, Integer time, AggregationCount.ThresholdType type, Number threshold) {
    	List<String> fields = new ArrayList<>();
        fields.add("user");
        fields.add("ip_src");
    	Map<String, Object> parameters = super.getParametersMap(grace, time, type, threshold, fields, Collections.emptyList(), 100);
                
        return parameters;
    }
}
