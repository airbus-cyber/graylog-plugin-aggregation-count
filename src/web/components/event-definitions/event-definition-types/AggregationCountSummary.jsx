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
import { extractDurationAndUnit } from 'components/common/TimeUnitInput';
import { TIME_UNITS } from 'components/event-definitions/event-definition-types/FilterForm';

class AggregationCountSummary extends React.Component {
    static propTypes = {
        config: PropTypes.string.isRequired,
    };

    render() {
        const { config } = this.props;
        const searchWithin = extractDurationAndUnit(config.search_within_ms, TIME_UNITS);
        const executeEvery = extractDurationAndUnit(config.execute_every_ms, TIME_UNITS);

        return (
            <React.Fragment>
                <tr>
                    <td>Stream:</td>
                    <td>{config.stream || 'No stream for this condition.'}</td>
                </tr>
                <tr>
                    <td>Threshold Type:</td>
                    <td>{config.threshold_type || 'No threshold type for this condition.'}</td>
                </tr>
                <tr>
                    <td>Threshold:</td>
                    <td>{config.threshold}</td>
                </tr>
                <tr>
                    <td>Search within:</td>
                    <td>{searchWithin.duration} {searchWithin.unit.toLowerCase()}</td>
                </tr>
                <tr>
                    <td>Execute search every:</td>
                    <td>{executeEvery.duration} {executeEvery.unit.toLowerCase()}</td>
                </tr>
                <tr>
                    <td>Grouping Fields:</td>
                    <td>{config.grouping_fields.join(', ') || 'No grouping fields for this condition.'}</td>
                </tr>
                <tr>
                    <td>Distinction Fields:</td>
                    <td>{config.distinction_fields.join(', ') || 'No distinction fields for this condition.'}</td>
                </tr>
                <tr>
                    <td>Comment:</td>
                    <td>{config.comment}</td>
                </tr>
                <tr>
                    <td>Search Query:</td>
                    <td>{config.search_query}</td>
                </tr>
            </React.Fragment>
        );
    }
}

export default AggregationCountSummary;