package com.airbus_cyber_security.graylog.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.graylog.events.contentpack.entities.EventProcessorConfigEntity;
import org.graylog.events.processor.EventProcessorConfig;
import org.graylog2.contentpacks.EntityDescriptorIds;
import org.graylog2.contentpacks.model.entities.references.ValueReference;
import org.graylog2.plugin.rest.ValidationResult;

import java.util.Set;

@AutoValue
@JsonTypeName(AggregationCountProcessorConfig.TYPE_NAME)
@JsonDeserialize(builder = AggregationCountProcessorConfig.Builder.class)
public abstract class AggregationCountProcessorConfig implements EventProcessorConfig {
    public static final String TYPE_NAME = "aggregation-count";

    private static final String FIELD_STREAM = "stream";
    private static final String FIELD_THRESHOLD_TYPE = "threshold_type";
    private static final String FIELD_THRESHOLD = "threshold";
    private static final String FIELD_TIME_RANGE = "time_range";
    private static final String FIELD_GRACE_PERIOD = "grace_period";
    private static final String FIELD_MESSAGE_BACKLOG = "message_backlog";
    private static final String FIELD_GROUPING_FIELDS = "grouping_fields";
    private static final String FIELD_DISTINCTION_FIELDS = "distinction_fields";
    private static final String FIELD_COMMENT = "comment";
    private static final String FIELD_SEARCH_QUERY = "search_query";
    private static final String FIELD_REPEAT_NOTIFICATIONS = "repeat_notifications";

    @JsonProperty(FIELD_STREAM)
    public abstract String stream();

    @JsonProperty(FIELD_THRESHOLD_TYPE)
    public abstract String thresholdType();

    @JsonProperty(FIELD_THRESHOLD)
    public abstract int threshold();

    @JsonProperty(FIELD_TIME_RANGE)
    public abstract int timeRange();

    @JsonProperty(FIELD_GRACE_PERIOD)
    public abstract int gracePeriod();

    @JsonProperty(FIELD_MESSAGE_BACKLOG)
    public abstract int messageBacklog();

    @JsonProperty(FIELD_GROUPING_FIELDS)
    public abstract Set<String> groupingFields();

    @JsonProperty(FIELD_DISTINCTION_FIELDS)
    public abstract Set<String> distinctionFields();

    @JsonProperty(FIELD_COMMENT)
    public abstract String comment();

    @JsonProperty(FIELD_SEARCH_QUERY)
    public abstract String searchQuery();

    @JsonProperty(FIELD_REPEAT_NOTIFICATIONS)
    public abstract boolean repeatNotifications();

    public static Builder builder() {
        return Builder.create();
    }

    public abstract Builder toBuilder();

    @AutoValue.Builder
    public static abstract class Builder implements EventProcessorConfig.Builder<Builder> {
        @JsonCreator
        public static Builder create() {
            return new AutoValue_AggregationCountProcessorConfig.Builder()
                    .type(TYPE_NAME);
        }

        @JsonProperty(FIELD_STREAM)
        public abstract Builder stream(String stream);

        @JsonProperty(FIELD_THRESHOLD_TYPE)
        public abstract Builder thresholdType(String thresholdType);

        @JsonProperty(FIELD_THRESHOLD)
        public abstract Builder threshold(int threshold);

        @JsonProperty(FIELD_TIME_RANGE)
        public abstract Builder timeRange(int timeRange);

        @JsonProperty(FIELD_GRACE_PERIOD)
        public abstract Builder gracePeriod(int gracePeriod);

        @JsonProperty(FIELD_MESSAGE_BACKLOG)
        public abstract Builder messageBacklog(int messageBacklog);

        @JsonProperty(FIELD_GROUPING_FIELDS)
        public abstract Builder groupingFields(Set<String> groupingFields);

        @JsonProperty(FIELD_DISTINCTION_FIELDS)
        public abstract Builder distinctionFields(Set<String> distinctionFields);

        @JsonProperty(FIELD_COMMENT)
        public abstract Builder comment(String comment);

        @JsonProperty(FIELD_SEARCH_QUERY)
        public abstract Builder searchQuery(String searchQuery);

        @JsonProperty(FIELD_REPEAT_NOTIFICATIONS)
        public abstract Builder repeatNotifications(boolean repeatNotifications);

        public abstract AggregationCountProcessorConfig build();
    }

    @Override
    public ValidationResult validate() {
        ValidationResult validationResult = new ValidationResult();
        if(stream() == null || stream().isEmpty()) {
            validationResult.addError(FIELD_STREAM, "Stream is mandatory");
        }
        if(thresholdType() == null || thresholdType().isEmpty()) {
            validationResult.addError(FIELD_THRESHOLD_TYPE, "Threshold type is mandatory");
        }
        if(threshold() < 0) {
            validationResult.addError(FIELD_THRESHOLD, "Threshold must be greater than 0.");
        }
        if(timeRange() < 0) {
            validationResult.addError(FIELD_TIME_RANGE, "Time range must be greater than 0.");
        }
        if(gracePeriod() < 0) {
            validationResult.addError(FIELD_GRACE_PERIOD, "Grace period must be greater than 0.");
        }
        if(messageBacklog() < 0) {
            validationResult.addError(FIELD_MESSAGE_BACKLOG, "Message backog must be greater than 0.");
        }
        return validationResult;
    }

    @Override
    public EventProcessorConfigEntity toContentPackEntity(EntityDescriptorIds entityDescriptorIds) {
        return AggregationCountProcessorConfigEntity.builder()
                .stream(ValueReference.of(stream()))
                .thresholdType(ValueReference.of(thresholdType()))
                .threshold(threshold())
                .timeRange(timeRange())
                .gracePeriod(gracePeriod())
                .messageBacklog(messageBacklog())
                .groupingFields(groupingFields())
                .distinctionFields(distinctionFields())
                .comment(ValueReference.of(comment()))
                .searchQuery(ValueReference.of(searchQuery()))
                .repeatNotifications(repeatNotifications())
                .build();
    }
}
