package com.airbus_cyber_security.graylog.events.processor.aggregation;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.graylog.events.event.EventFactory;
import org.graylog.events.notifications.EventNotificationSettings;
import org.graylog.events.processor.DBEventProcessorStateService;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.events.processor.EventProcessorDependencyCheck;
import org.graylog.events.processor.EventProcessorPreconditionException;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.messages.Messages;
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

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AggregationCountProcessorTest {

    private final int threshold = 100;

    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();

    @Mock
    private EventFactory eventFactory;
    @Mock
    private DBEventProcessorStateService stateService;
    @Mock
    private EventProcessorDependencyCheck eventProcessorDependencyCheck;
    @Mock
    private MoreSearch moreSearch;
    @Mock
    private Messages messages;

    @Test
    public void testEvents() {
        final DateTime now = DateTime.now(DateTimeZone.UTC);
        final AbsoluteRange timeRange = AbsoluteRange.create(now.minusHours(1), now.plusHours(1));
        final EventDefinitionDto eventDefinitionDto = getEventDefinitionDto(getAggregationCountProcessorConfig());
        final AggregationCountProcessorParameters parameters = AggregationCountProcessorParameters.builder()
                .timerange(timeRange)
                .build();

        AggregationCountProcessor eventProcessor = new AggregationCountProcessor(eventDefinitionDto, eventProcessorDependencyCheck,
                stateService, moreSearch, messages);
        assertThatCode(() -> eventProcessor.createEvents(eventFactory, parameters, (events) -> {}))
                .hasMessageContaining(eventDefinitionDto.title())
                .hasMessageContaining(eventDefinitionDto.id())
                .hasMessageContaining(timeRange.from().toString())
                .hasMessageContaining(timeRange.to().toString())
                .isInstanceOf(EventProcessorPreconditionException.class);
    }

    @Test
    public void testRunCheckWithAggregateMorePositive() {
        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        groupingFields.add("ip_src");

        List<String> distinctionFields = new ArrayList<>();

        AggregationCountProcessorConfig config = getAggregationCountProcessorConfigWithFields(AggregationCountUtils.ThresholdType.MORE, threshold, groupingFields, distinctionFields, 100);

        searchTermsThreeAggregateShouldReturn(threshold + 1L);
        searchResultShouldReturn();
        AggregationCountUtils aggregationCountUtils = new AggregationCountUtils(config);
        AggregationCountCheckResult result = aggregationCountUtils.runCheck(config, moreSearch);

        String resultDescription = "Stream had " + (threshold+1) + " messages in the last 0 milliseconds with trigger condition more "
                + config.threshold() + " messages with the same value of the fields " + String.join(", ", config.groupingFields())
                + ". (Executes every: 0 milliseconds)";
        assertEquals(resultDescription, result.getResultDescription());
        assertEquals("Matching messages ", 3, result.getMessageSummaries().size());
    }

    @Test
    public void testRunCheckWithAggregateLessPositive() {
        final AggregationCountUtils.ThresholdType type = AggregationCountUtils.ThresholdType.LESS;

        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        groupingFields.add("ip_src");

        List<String> distinctionFields = new ArrayList<>();
        distinctionFields.add("user");

        AggregationCountProcessorConfig config = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields, 100);

        searchTermsOneAggregateShouldReturn(threshold + 1L);
        searchResultShouldReturn();

        AggregationCountUtils aggregationCountUtils = new AggregationCountUtils(config);
        AggregationCountCheckResult result = aggregationCountUtils.runCheck(config, moreSearch);

        String resultDescription = "Stream had 1 messages in the last 0 milliseconds with trigger condition less "
                + config.threshold() + " messages with the same value of the fields " + String.join(", ", config.groupingFields())
                + ", and with distinct values of the fields " + String.join(", ", config.distinctionFields()) + ". (Executes every: 0 milliseconds)";
        assertEquals(resultDescription, result.getResultDescription());
        assertEquals("Matching messages ", 1, result.getMessageSummaries().size());
    }

    @Test
    public void testRunCheckWithAggregateMoreNegative() {
        final AggregationCountUtils.ThresholdType type = AggregationCountUtils.ThresholdType.MORE;

        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        List<String> distinctionFields = new ArrayList<>();
        distinctionFields.add("user");

        AggregationCountProcessorConfig config = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields, 100);

        searchTermsOneAggregateShouldReturn(threshold - 1L);
        searchResultShouldReturn();

        AggregationCountUtils aggregationCountUtils = new AggregationCountUtils(config);
        AggregationCountCheckResult result = aggregationCountUtils.runCheck(config, moreSearch);
        assertEquals("", result.getResultDescription());
        assertEquals("Matching messages ", 0, result.getMessageSummaries().size());
    }

    @Test
    public void testRunCheckWithAggregateLessNegative() {
        final AggregationCountUtils.ThresholdType type = AggregationCountUtils.ThresholdType.LESS;

        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");

        List<String> distinctionFields = new ArrayList<>();

        AggregationCountProcessorConfig config = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields, 100);

        searchTermsThreeAggregateShouldReturn(threshold +1L);
        searchResultShouldReturn();

        AggregationCountUtils aggregationCountUtils = new AggregationCountUtils(config);
        AggregationCountCheckResult result = aggregationCountUtils.runCheck(config, moreSearch);
        assertEquals("", result.getResultDescription());
        assertEquals("Matching messages ", 0, result.getMessageSummaries().size());
    }

    @Test
    public void testRunCheckWithAggregateMorePositiveWithNoBacklog() {
        final AggregationCountUtils.ThresholdType type = AggregationCountUtils.ThresholdType.MORE;

        List<String> groupingFields = new ArrayList<>();
        groupingFields.add("user");
        groupingFields.add("ip_src");

        List<String> distinctionFields = new ArrayList<>();

        AggregationCountProcessorConfig config = getAggregationCountProcessorConfigWithFields(type, threshold, groupingFields, distinctionFields, 0);

        searchTermsThreeAggregateShouldReturn(threshold + 1L);
        searchResultShouldReturn();
        AggregationCountUtils aggregationCountUtils = new AggregationCountUtils(config);
        AggregationCountCheckResult result = aggregationCountUtils.runCheck(config, moreSearch);
        String resultDescription = "Stream had " + (threshold+1) + " messages in the last 0 milliseconds with trigger condition more "
                + config.threshold() + " messages with the same value of the fields " + String.join(", ", config.groupingFields())
                + ". (Executes every: 0 milliseconds)";
        assertEquals(resultDescription, result.getResultDescription());
        assertEquals("Matching messages ", 0, result.getMessageSummaries().size());
    }

    @Test
    public void testRunCheckWithNoGroupingFieldsAndNoDistinctFields() {
        final AggregationCountUtils.ThresholdType type = AggregationCountUtils.ThresholdType.MORE;

        List<String> groupingFields = new ArrayList<>();
        List<String> distinctionFields = new ArrayList<>();
        final int thresholdTest = 9;

        AggregationCountProcessorConfig config = getAggregationCountProcessorConfigWithFields(type, thresholdTest, groupingFields, distinctionFields, 0);

        searchCountShouldReturn(thresholdTest + 1L);
        AggregationCountUtils aggregationCountUtils = new AggregationCountUtils(config);
        AggregationCountCheckResult result = aggregationCountUtils.runCheck(config, moreSearch);

        String resultDescription = "Stream had 10 messages in the last 0 milliseconds with trigger condition more 9 messages. (Executes every: 0 milliseconds)";
        assertEquals("ResultDescription", resultDescription, result.getResultDescription());
    }

    private AggregationCountProcessorConfig getAggregationCountProcessorConfig() {
        return AggregationCountProcessorConfig.builder()
                .stream("main stream")
                .thresholdType(AggregationCountUtils.ThresholdType.MORE.getDescription())
                .threshold(threshold)
                .searchWithinMs(2*1000)
                .executeEveryMs(2*60*1000)
                .messageBacklog(1)
                .groupingFields(new HashSet<>())
                .distinctionFields(new HashSet<>())
                .comment("test comment")
                .searchQuery("*")
                .repeatNotifications(false)
                .build();
    }

    private AggregationCountProcessorConfig getAggregationCountProcessorConfigWithFields(AggregationCountUtils.ThresholdType type,
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

    private EventDefinitionDto getEventDefinitionDto(AggregationCountProcessorConfig config) {
        return EventDefinitionDto.builder()
                .id("dto-id")
                .title("Test Correlation")
                .description("A test correlation event processors")
                .config(config)
                .alert(false)
                .keySpec(ImmutableList.of())
                .notificationSettings(EventNotificationSettings.withGracePeriod(60000))
                .priority(1)
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
