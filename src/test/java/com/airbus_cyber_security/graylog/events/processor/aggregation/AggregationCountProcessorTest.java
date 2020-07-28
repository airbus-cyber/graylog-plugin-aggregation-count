package com.airbus_cyber_security.graylog.events.processor.aggregation;

import com.google.common.collect.ImmutableList;
import org.graylog.events.event.EventFactory;
import org.graylog.events.notifications.EventNotificationSettings;
import org.graylog.events.processor.DBEventProcessorStateService;
import org.graylog.events.processor.EventDefinitionDto;
import org.graylog.events.processor.EventProcessorDependencyCheck;
import org.graylog.events.processor.EventProcessorPreconditionException;
import org.graylog.events.search.MoreSearch;
import org.graylog2.indexer.messages.Messages;
import org.graylog2.plugin.indexer.searches.timeranges.AbsoluteRange;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class AggregationCountProcessorTest {

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

    private AggregationCountProcessor subject;

    @Before
    public void setUp() {
        DateTime now = DateTime.now(DateTimeZone.UTC);
        AbsoluteRange timeRange = AbsoluteRange.create(now.minusHours(1), now.plusHours(1));
        AggregationCountProcessorConfig configuration = AggregationCountProcessorConfig.builder()
                .stream("main stream")
                .thresholdType(AggregationCount.ThresholdType.MORE.getDescription())
                .threshold(100)
                .searchWithinMs(2 * 1000)
                .executeEveryMs(2 * 60 * 1000)
                .messageBacklog(1)
                .groupingFields(new HashSet<>())
                .distinctionFields(new HashSet<>())
                .comment("test comment")
                .searchQuery("*")
                .repeatNotifications(false)
                .build();
        EventDefinitionDto eventDefinitionDto = EventDefinitionDto.builder()
                .id("dto-id")
                .title("Test Correlation")
                .description("A test correlation event processors")
                .config(configuration)
                .alert(false)
                .keySpec(ImmutableList.of())
                .notificationSettings(EventNotificationSettings.withGracePeriod(60000))
                .priority(1)
                .build();

        this.subject = new AggregationCountProcessor(eventDefinitionDto, eventProcessorDependencyCheck,
                stateService, moreSearch, messages);

    }

    @Test
    public void createEventsShouldThrowWhenMessagesAreNotYetIndexed() {
        final DateTime now = DateTime.now(DateTimeZone.UTC);
        final AbsoluteRange timeRange = AbsoluteRange.create(now.minusHours(1), now.plusHours(1));
        final AggregationCountProcessorParameters parameters = AggregationCountProcessorParameters.builder()
                .timerange(timeRange)
                .build();

        assertThatThrownBy(() -> this.subject.createEvents(eventFactory, parameters, (events) -> {}))
                .hasMessageContaining("Test Correlation")
                .hasMessageContaining("dto-id")
                .hasMessageContaining(timeRange.from().toString())
                .hasMessageContaining(timeRange.to().toString())
                .isInstanceOf(EventProcessorPreconditionException.class);
    }

}
