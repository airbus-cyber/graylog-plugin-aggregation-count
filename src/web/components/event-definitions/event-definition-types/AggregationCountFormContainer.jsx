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

import { Spinner } from 'components/common';

import connect from 'stores/connect';
import { FieldTypesStore } from 'views/stores/FieldTypesStore';
import withStreams from 'components/event-definitions/event-definition-types/withStreams';

import AggregationCountForm from './AggregationCountForm';

// We currently don't support creating Events from these Streams, since they also contain Events
// and it's not possible to access custom Fields defined in them.
const HIDDEN_STREAMS = [
    '000000000000000000000002',
    '000000000000000000000003',
];

class AggregationCountFormContainer extends React.Component {
    static propTypes = {
        eventDefinition: PropTypes.object.isRequired,
        validation: PropTypes.object.isRequired,
        onChange: PropTypes.func.isRequired,
        streams: PropTypes.array.isRequired,
        fieldTypes: PropTypes.object.isRequired,
    };

    render() {
        const { fieldTypes, ...otherProps } = this.props;

        const isLoading = typeof fieldTypes.all !== 'object';

        if (isLoading) {
            return <Spinner text="Loading Filter & Aggregation Count Information..." />;
        }
        return <AggregationCountForm allFieldTypes={fieldTypes.all.toJS()} {...otherProps} />;
    }
}

export default connect(withStreams(AggregationCountFormContainer, HIDDEN_STREAMS), {
    fieldTypes: FieldTypesStore,
});