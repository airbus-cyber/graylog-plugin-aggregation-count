package com.airbus_cyber_security.graylog;

import com.airbus_cyber_security.graylog.config.AggregationCountProcessorConfig;
import com.google.common.collect.ImmutableList;
import org.graylog.events.event.EventFactory;
import org.graylog.events.notifications.EventNotificationSettings;
import org.graylog.events.processor.DBEventProcessorStateService;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.events.processor.EventProcessorDependencyCheck;
import org.graylog.events.processor.EventProcessorPreconditionException;
import org.graylog2.indexer.messages.Messages;
import org.graylog2.indexer.searches.Searches;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThatCode;

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
    private Searches searches;
    @Mock
    private Messages messages;

    @Test
    public void testEvents() {
        final DateTime now = DateTime.now(DateTimeZone.UTC);
        final AbsoluteRange timeRange = AbsoluteRange.create(now.minusHours(1), now.plusHours(1));
        final EventDefinitionDto eventDefinitionDto = EventDefinitionDto.builder()
                .id("dto-id")
                .title("Test Correlation")
                .description("A test correlation event processors")
                .config(getAggregationCountProcessorConfig())
                .alert(false)
                .keySpec(ImmutableList.of())
                .notificationSettings(EventNotificationSettings.withGracePeriod(60000))
                .priority(1)
                .build();
        final AggregationCountProcessorParameters parameters = AggregationCountProcessorParameters.builder()
                .timerange(timeRange)
                .build();

        AggregationCountProcessor eventProcessor = new AggregationCountProcessor(eventDefinitionDto, eventProcessorDependencyCheck,
                stateService, searches, messages);
        assertThatCode(() -> eventProcessor.createEvents(eventFactory, parameters, (events) -> {}))
                .hasMessageContaining(eventDefinitionDto.title())
                .hasMessageContaining(eventDefinitionDto.id())
                .hasMessageContaining(timeRange.from().toString())
                .hasMessageContaining(timeRange.to().toString())
                .isInstanceOf(EventProcessorPreconditionException.class);
    }

    private AggregationCountProcessorConfig getAggregationCountProcessorConfig() {
        return AggregationCountProcessorConfig.builder()
                .stream("main stream")
                .thresholdType(AggregationCountUtils.ThresholdType.MORE.getDescription())
                .threshold(threshold)
                .timeRange(2)
                .gracePeriod(2)
                .messageBacklog(1)
                .groupingFields(new HashSet<>())
                .distinctionFields(new HashSet<>())
                .comment("test comment")
                .searchQuery("*")
                .repeatNotifications(false)
                .build();
    }
}
