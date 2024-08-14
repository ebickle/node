// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/turboshaft/build-graph-phase.h"

#include "src/compiler/js-heap-broker.h"
#include "src/compiler/node-origin-table.h"
#include "src/compiler/phase.h"
#include "src/compiler/pipeline-data-inl.h"
#include "src/compiler/turboshaft/graph-builder.h"
#include "src/compiler/turboshaft/phase.h"

namespace v8::internal::compiler::turboshaft {

base::Optional<BailoutReason> BuildGraphPhase::Run(
    PipelineData* data, Zone* temp_zone,
    compiler::TFPipelineData* turbofan_data, Linkage* linkage) {
  Schedule* schedule = turbofan_data->schedule();
  turbofan_data->reset_schedule();
  DCHECK_NOT_NULL(schedule);

  UnparkedScopeIfNeeded scope(data->broker());

  // Construct a new graph.
  ZoneWithNamePointer<SourcePositionTable, kGraphZoneName> source_positions(
      turbofan_data->source_positions());
  ZoneWithNamePointer<NodeOriginTable, kGraphZoneName> node_origins(
      turbofan_data->node_origins());
  data->InitializeGraphComponentWithGraphZone(turbofan_data->ReleaseGraphZone(),
                                              source_positions, node_origins);

  if (auto bailout =
          turboshaft::BuildGraph(data, schedule, temp_zone, linkage)) {
    return bailout;
  }
  return {};
}

}  // namespace v8::internal::compiler::turboshaft
