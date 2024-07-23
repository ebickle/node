// Flags:  --enable-source-maps

import '../../../common/index.mjs';

interface Block {
  /** line
   *
   * blocks */
}

class Foo {
  constructor() {
    throw new Error('message');
  }
}

new Foo();

// To recreate:
//
// npx --package typescript tsc --module nodenext --target esnext --outDir test/fixtures/source-map/output --sourceMap test/fixtures/source-map/output/source_map_throw_construct.mts
