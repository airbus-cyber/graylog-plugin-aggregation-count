package com.airbus_cyber_security.graylog.events.processor.aggregation.checks;

public enum ThresholdType {

    MORE("MORE"),
    LESS("LESS");

    private final String description;

    ThresholdType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public static ThresholdType fromString(String typeString) {
        for (ThresholdType type : ThresholdType.values()) {
            if (type.description.equalsIgnoreCase(typeString)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown ThresholdType value: " + typeString);
    }
}

