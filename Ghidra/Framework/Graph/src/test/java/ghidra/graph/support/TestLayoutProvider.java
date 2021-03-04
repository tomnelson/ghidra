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
package ghidra.graph.support;

import java.awt.geom.Point2D;
import java.util.Collection;

import javax.swing.Icon;

import ghidra.graph.graphs.TestEdge;
import ghidra.graph.graphs.AbstractTestVertex;
import ghidra.graph.viewer.layout.LayoutProvider;
import ghidra.graph.viewer.renderer.ArticulatedEdgeRenderer;
import ghidra.graph.viewer.shape.ArticulatedEdgeTransformer;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import org.jungrapht.visualization.layout.algorithms.DAGLayoutAlgorithm;
import org.jungrapht.visualization.layout.algorithms.LayoutAlgorithm;
import org.jungrapht.visualization.layout.model.DefaultLayoutModel;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;

/**
 * A layout provider used for testing.
 */
public class TestLayoutProvider implements LayoutProvider<AbstractTestVertex, TestEdge, TestVisualGraph> {

	private ArticulatedEdgeTransformer<AbstractTestVertex, TestEdge> edgeShapeTransformer =
		new ArticulatedEdgeTransformer<>();
	private ArticulatedEdgeRenderer<AbstractTestVertex, TestEdge> edgeRenderer =
		new ArticulatedEdgeRenderer<>();

	@Override
	public TestGraphLayout getLayout(TestVisualGraph g, TaskMonitor monitor)
			throws CancelledException {
		LayoutModel<AbstractTestVertex> layoutModel =
				LayoutModel.<AbstractTestVertex>builder().build();
		layoutModel.setGraph(g);
		LayoutAlgorithm<AbstractTestVertex> layoutAlgorithm =
				DAGLayoutAlgorithm.<AbstractTestVertex,Object>builder().build();
		layoutAlgorithm.visit(layoutModel);

//		Collection<AbstractTestVertex> vertices = g.getVertices();
//		for (AbstractTestVertex v : vertices) {
//			layoutModel.set(v, )
//			Point p = layoutModel.apply(v);
//			v.setLocation(p);
//		}

		return new TestGraphLayout(layoutModel);
	}

	// template method to allow tests to override the Jung layout in use
	protected LayoutModel<AbstractTestVertex> createJungLayout(TestVisualGraph g) {
		LayoutModel<AbstractTestVertex> layoutModel =
				LayoutModel.<AbstractTestVertex>builder().build();
		LayoutAlgorithm<AbstractTestVertex> layoutAlgorithm =
				DAGLayoutAlgorithm.<AbstractTestVertex,Object>builder().build();
		layoutAlgorithm.visit(layoutModel);
		return layoutModel;
	}

	@Override
	public String getLayoutName() {
		return "Test Layout";
	}

	@Override
	public Icon getActionIcon() {
		return null;
	}

	@Override
	public int getPriorityLevel() {
		return 0;
	}

}
