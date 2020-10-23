/*
 * graylog-plugin-aggregation-count Source Code
 * Copyright (C) 2018-2020 - Airbus CyberSecurity (SAS) - All rights reserved
 *
 * This file is part of the graylog-plugin-aggregation-count GPL Source Code.
 *
 * graylog-plugin-aggregation-count Source Code is free software:
 * you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this code.  If not, see <http://www.gnu.org/licenses/>.
 */

import React from 'react';
import PropTypes from 'prop-types';
import lodash from 'lodash';
import FormsUtils from 'util/FormsUtils';
import { naturalSortIgnoreCase } from 'util/SortUtils';

import { ControlLabel, FormGroup, HelpBlock } from 'components/graylog';
import { Select, MultiSelect } from 'components/common';
import { Input } from 'components/bootstrap';
import TimeUnitFormGroup from './TimeUnitFormGroup';

import { defaultCompare } from 'views/logic/DefaultCompare';

class AggregationCountForm extends React.Component {
    // Memoize function to only format fields when they change. Use joined fieldNames as cache key.
    formatFields = lodash.memoize(
        (fieldTypes) => {
            return fieldTypes
                .sort((ftA, ftB) => defaultCompare(ftA.name, ftB.name))
                .map((fieldType) => {
                    return {
                        label: `${fieldType.name} – ${fieldType.value.type.type}`,
                        value: fieldType.name,
                    };
                }
            );
        },
        (fieldTypes) => fieldTypes.map((ft) => ft.name).join('-'),
    );

    static propTypes = {
        eventDefinition: PropTypes.object.isRequired,
        validation: PropTypes.object.isRequired,
        onChange: PropTypes.func.isRequired,
        streams: PropTypes.array.isRequired,
        allFieldTypes: PropTypes.array.isRequired,
    };

    formatStreamIds = () => {
        const { streams } = this.props;

        return streams.map(s => s.id)
            .map(streamId => streams.find(s => s.id === streamId) || streamId)
            .map((streamOrId) => {
                const stream = (typeof streamOrId === 'object' ? streamOrId : { title: streamOrId, id: streamOrId });
                return {
                    label: stream.title,
                    value: stream.id,
                };
            })
            .sort((s1, s2) => naturalSortIgnoreCase(s1.label, s2.label));
    };

    propagateChange = (key, value) => {
        const { eventDefinition, onChange } = this.props;
        const config = lodash.cloneDeep(eventDefinition.config);
        config[key] = value;
        onChange('config', config);
    };

    handleChange = (event) => {
        const { name } = event.target;
        this.propagateChange(name, FormsUtils.getValueFromInput(event.target));
    };

    handleSearchWithinMsChange = (nextValue) => {
        this.propagateChange('search_within_ms', nextValue);
    };

    handleExecuteEveryMsChange = (nextValue) => {
        this.propagateChange('execute_every_ms', nextValue);
    };

    handleStreamChange = (nextValue) => {
        this.propagateChange('stream', nextValue);
    };

    handleThresholdTypeChange = (nextValue) => {
        this.propagateChange('threshold_type', nextValue);
    };

    handleGroupByChange = (selected) => {
        const nextValue = selected === '' ? [] : selected.split(',');
        this.propagateChange('grouping_fields', nextValue)
    };

    handleDistinctByChange = (selected) => {
        const nextValue = selected === '' ? [] : selected.split(',');
        this.propagateChange('distinction_fields', nextValue)
    };

    availableThresholdTypes = () => {
        return [
            {value: 'MORE', label: 'more than'},
            {value: 'LESS', label: 'less than'},
        ];
    };

    render() {
        const { eventDefinition, validation, allFieldTypes } = this.props;
        const formattedStreams = this.formatStreamIds();
        const formattedFields = this.formatFields(allFieldTypes);

        return (
            <React.Fragment>
                <FormGroup controlId="stream"
                           validationState={validation.errors.stream ? 'error' : null}>
                    <ControlLabel>Stream</ControlLabel>
                    <Select id="stream"
                            placeholder="Select Stream"
                            required
                            options={formattedStreams}
                            matchProp="value"
                            value={lodash.defaultTo(eventDefinition.stream, eventDefinition.config.stream)}
                            onChange={this.handleStreamChange}
                    />
                    <HelpBlock>
                        Select streams the search should include. Searches in all streams if empty.
                    </HelpBlock>
                </FormGroup>
                <FormGroup controlId="threshold_type"
                           validationState={validation.errors.threshold_type ? 'error' : null}>
                    <ControlLabel>Threshold Type</ControlLabel>
                    <Select id="threshold_type"
                            required
                            options={this.availableThresholdTypes()}
                            matchProp="value"
                            value={lodash.defaultTo(eventDefinition.threshold_type, eventDefinition.config.threshold_type)}
                            onChange={this.handleThresholdTypeChange}
                    />
                    <HelpBlock>
                        Select condition to trigger alert: when there are more or less messages in the main stream than the threshold
                    </HelpBlock>
                </FormGroup>
                <ControlLabel>Threshold</ControlLabel>
                <Input
                    id="threshold"
                    type="number"
                    name="threshold"
                    help="Value which triggers an alert if crossed"
                    value={lodash.defaultTo(eventDefinition.threshold, eventDefinition.config.threshold)}
                    onChange={this.handleChange}
                />
                <TimeUnitFormGroup
                    label="Search within the last"
                    value={lodash.defaultTo(eventDefinition.search_within_ms, eventDefinition.config.search_within_ms)}
                    update={this.handleSearchWithinMsChange}
                    errors={validation.errors.search_within_ms}
                />
                <TimeUnitFormGroup
                    label="Execute search every"
                    value={lodash.defaultTo(eventDefinition.execute_every_ms, eventDefinition.config.execute_every_ms)}
                    update={this.handleExecuteEveryMsChange}
                    errors={validation.errors.execute_every_ms}
                />
                <FormGroup controlId="group-by">
                    <ControlLabel>Group by Field(s) <small className="text-muted">(Optional)</small></ControlLabel>
                    <MultiSelect id="group-by"
                                 matchProp="label"
                                 onChange={this.handleGroupByChange}
                                 options={formattedFields}
                                 ignoreAccents={false}
                                 value={lodash.defaultTo(eventDefinition.config.grouping_fields, []).join(',')}
                                 allowCreate />
                    <HelpBlock>
                        Fields that should be checked to count messages with the same values
                    </HelpBlock>
                </FormGroup>
                <FormGroup controlId="distinct-by">
                    <ControlLabel>Distinction Field(s) <small className="text-muted">(Optional)</small></ControlLabel>
                    <MultiSelect id="distinct-by"
                                 matchProp="label"
                                 onChange={this.handleDistinctByChange}
                                 options={formattedFields}
                                 ignoreAccents={false}
                                 value={lodash.defaultTo(eventDefinition.config.distinction_fields, []).join(',')}
                                 allowCreate />
                    <HelpBlock>
                        Fields that should be checked to count messages with distinct values
                    </HelpBlock>
                </FormGroup>
                <ControlLabel>Comment <small className="text-muted">(Optional)</small></ControlLabel>
                <Input
                    id="comment"
                    type="text"
                    name="comment"
                    help="Comment about the configuration"
                    value={lodash.defaultTo(eventDefinition.comment, eventDefinition.config.comment)}
                    onChange={this.handleChange}
                />
                <ControlLabel>Search Query <small className="text-muted">(Optional)</small></ControlLabel>
                <Input
                    id="search_query"
                    type="text"
                    name="search_query"
                    help="Query string that should be used to filter messages in the stream"
                    value={lodash.defaultTo(eventDefinition.search_query, eventDefinition.config.search_query)}
                    onChange={this.handleChange}
                />
            </React.Fragment>
        );
    }
}

export default AggregationCountForm;