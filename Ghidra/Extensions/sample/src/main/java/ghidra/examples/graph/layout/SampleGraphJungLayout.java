/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.examples.graph.layout;

import ghidra.examples.graph.*;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.JungWrappingVisualGraphLayoutAdapter;
import org.jungrapht.visualization.layout.model.LayoutModel;

/**
 * A {@link SampleGraphPlugin} layout that can be used to apply existing Jung layouts.
 */
public class SampleGraphJungLayout
		extends JungWrappingVisualGraphLayoutAdapter<SampleVertex, SampleEdge> {

	public SampleGraphJungLayout(LayoutModel<SampleVertex> jungLayout) {
		super(jungLayout);
	}

	@Override
	protected LayoutModel<SampleVertex> cloneJungLayout(
			VisualGraph<SampleVertex, SampleEdge> newGraph) {

		LayoutModel<SampleVertex> newJungLayout = cloneJungLayout(newGraph);
		return new SampleGraphJungLayout(newJungLayout);
	}

	LayoutModel<?> getJungLayout() {
		return delegate;
	}
}
