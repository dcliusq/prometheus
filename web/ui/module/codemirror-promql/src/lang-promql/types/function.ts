// Copyright 2021 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {
  Abs,
  Absent,
  AbsentOverTime,
  AvgOverTime,
  Ceil,
  Changes,
  Clamp,
  ClampMax,
  ClampMin,
  CountOverTime,
  DayOfMonth,
  DayOfWeek,
  DaysInMonth,
  Delta,
  Deriv,
  Exp,
  Floor,
  HistogramQuantile,
  HoltWinters,
  Hour,
  Idelta,
  Increase,
  Irate,
  LabelJoin,
  LabelReplace,
  LastOverTime,
  Ln,
  Log10,
  Log2,
  MaxOverTime,
  MinOverTime,
  Minute,
  Month,
  PredictLinear,
  PresentOverTime,
  QuantileOverTime,
  Rate,
  Resets,
  Round,
  Scalar,
  Sgn,
  Sort,
  SortDesc,
  Sqrt,
  StddevOverTime,
  StdvarOverTime,
  SumOverTime,
  Time,
  Timestamp,
  Vector,
  Year,
} from 'lezer-promql';

export enum ValueType {
  none = 'none',
  vector = 'vector',
  scalar = 'scalar',
  matrix = 'matrix',
  string = 'string',
}

export interface PromQLFunction {
  name: string;
  argTypes: ValueType[];
  variadic: number;
  returnType: ValueType;
}

// promqlFunctions is a list of all functions supported by PromQL, including their types.
// Based on https://github.com/prometheus/prometheus/blob/master/promql/parser/functions.go#L26
const promqlFunctions: { [key: number]: PromQLFunction } = {
  [Abs]: {
    name: 'abs',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Absent]: {
    name: 'absent',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [AbsentOverTime]: {
    name: 'absent_over_time',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [AvgOverTime]: {
    name: 'avg_over_time',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Ceil]: {
    name: 'ceil',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Changes]: {
    name: 'changes',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Clamp]: {
    name: 'clamp',
    argTypes: [ValueType.vector, ValueType.scalar, ValueType.scalar],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [ClampMax]: {
    name: 'clamp_max',
    argTypes: [ValueType.vector, ValueType.scalar],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [ClampMin]: {
    name: 'clamp_min',
    argTypes: [ValueType.vector, ValueType.scalar],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [CountOverTime]: {
    name: 'count_over_time',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [DaysInMonth]: {
    name: 'days_in_month',
    argTypes: [ValueType.vector],
    variadic: 1,
    returnType: ValueType.vector,
  },
  [DayOfMonth]: {
    name: 'day_of_month',
    argTypes: [ValueType.vector],
    variadic: 1,
    returnType: ValueType.vector,
  },
  [DayOfWeek]: {
    name: 'day_of_week',
    argTypes: [ValueType.vector],
    variadic: 1,
    returnType: ValueType.vector,
  },
  [Delta]: {
    name: 'delta',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Deriv]: {
    name: 'deriv',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Exp]: {
    name: 'exp',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Floor]: {
    name: 'floor',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [HistogramQuantile]: {
    name: 'histogram_quantile',
    argTypes: [ValueType.scalar, ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [HoltWinters]: {
    name: 'holt_winters',
    argTypes: [ValueType.matrix, ValueType.scalar, ValueType.scalar],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Hour]: {
    name: 'hour',
    argTypes: [ValueType.vector],
    variadic: 1,
    returnType: ValueType.vector,
  },
  [Idelta]: {
    name: 'idelta',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Increase]: {
    name: 'increase',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Irate]: {
    name: 'irate',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [LabelReplace]: {
    name: 'label_replace',
    argTypes: [ValueType.vector, ValueType.string, ValueType.string, ValueType.string, ValueType.string],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [LabelJoin]: {
    name: 'label_join',
    argTypes: [ValueType.vector, ValueType.string, ValueType.string, ValueType.string],
    variadic: -1,
    returnType: ValueType.vector,
  },
  [LastOverTime]: {
    name: 'last_over_time',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Ln]: {
    name: 'ln',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Log10]: {
    name: 'log10',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Log2]: {
    name: 'log2',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [MaxOverTime]: {
    name: 'max_over_time',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [MinOverTime]: {
    name: 'min_over_time',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Minute]: {
    name: 'minute',
    argTypes: [ValueType.vector],
    variadic: 1,
    returnType: ValueType.vector,
  },
  [Month]: {
    name: 'month',
    argTypes: [ValueType.vector],
    variadic: 1,
    returnType: ValueType.vector,
  },
  [PredictLinear]: {
    name: 'predict_linear',
    argTypes: [ValueType.matrix, ValueType.scalar],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [PresentOverTime]: {
    name: 'present_over_time',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [QuantileOverTime]: {
    name: 'quantile_over_time',
    argTypes: [ValueType.scalar, ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Rate]: {
    name: 'rate',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Resets]: {
    name: 'resets',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Round]: {
    name: 'round',
    argTypes: [ValueType.vector, ValueType.scalar],
    variadic: 1,
    returnType: ValueType.vector,
  },
  [Scalar]: {
    name: 'scalar',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.scalar,
  },
  [Sgn]: {
    name: 'sgn',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Sort]: {
    name: 'sort',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [SortDesc]: {
    name: 'sort_desc',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Sqrt]: {
    name: 'sqrt',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [StddevOverTime]: {
    name: 'stddev_over_time',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [StdvarOverTime]: {
    name: 'stdvar_over_time',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [SumOverTime]: {
    name: 'sum_over_time',
    argTypes: [ValueType.matrix],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Time]: {
    name: 'time',
    argTypes: [],
    variadic: 0,
    returnType: ValueType.scalar,
  },
  [Timestamp]: {
    name: 'timestamp',
    argTypes: [ValueType.vector],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Vector]: {
    name: 'vector',
    argTypes: [ValueType.scalar],
    variadic: 0,
    returnType: ValueType.vector,
  },
  [Year]: {
    name: 'year',
    argTypes: [ValueType.vector],
    variadic: 1,
    returnType: ValueType.vector,
  },
};

export function getFunction(id: number): PromQLFunction {
  return promqlFunctions[id];
}
