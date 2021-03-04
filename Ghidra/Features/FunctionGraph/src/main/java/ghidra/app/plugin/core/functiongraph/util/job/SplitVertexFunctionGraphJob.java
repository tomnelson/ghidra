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
package ghidra.app.plugin.core.functiongraph.util.job;

import java.awt.Rectangle;
import java.awt.geom.Point2D;
import java.util.*;

import org.apache.commons.collections4.IterableUtils;
import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FGData;
import ghidra.graph.job.AbstractAnimatorJob;
import ghidra.graph.viewer.GraphViewerUtils;
import org.jgrapht.Graph;
import org.jungrapht.visualization.VisualizationServer;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.layout.util.Caching;

public class SplitVertexFunctionGraphJob extends AbstractAnimatorJob {

	private static final int DURATION = 1500;

	private final VisualizationServer<FGVertex, FGEdge> viewer;
	private LayoutModel<FGVertex> layoutModel;
	private final FGVertex toSplitVertex;
	private final FGVertex parentVertex;
	private final FGVertex childVertex;

	private Point parentStart;
	private Point childStart;
	private Point parentDestination;
	private Point childDestination;

	private final boolean useAnimation;

	private final FGController controller;

	public SplitVertexFunctionGraphJob(FGController controller,
			VisualizationServer<FGVertex, FGEdge> viewer, FGVertex toSplitVertex,
			FGVertex newParentVertex, FGVertex newChildVertex, boolean useAnimation) {
		this.controller = controller;
		this.viewer = viewer;
		this.toSplitVertex = toSplitVertex;
		this.parentVertex = newParentVertex;
		this.childVertex = newChildVertex;
		this.useAnimation = useAnimation;
		this.layoutModel = viewer.getVisualizationModel().getLayoutModel();

		updateOpacity(0D); // don't paint the new vertices or edges initially
	}

	@Override
	public boolean canShortcut() {
		return false;
	}

	@Override
	public void shortcut() {
		throw new UnsupportedOperationException("Cannot cancel this job: " + this);
	}

	@Override
	protected Animator createAnimator() {
		// don't paint these vertices initially
		parentVertex.setAlpha(0D);
		childVertex.setAlpha(0D);

		initializeVertexLocations();

		if (!useAnimation) {
			return null;
		}

		updateOpacity(0);

		Animator newAnimator =
			PropertySetter.createAnimator(DURATION, this, "percentComplete", 0.0, 1.0);
		newAnimator.setAcceleration(0f);
		newAnimator.setDeceleration(0.8f);

		return newAnimator;
	}

	@Override
	protected void finished() {
		if (isShortcut) {
			initializeVertexLocations();
		}

		clearLocationCache();
		layoutModel.set(parentVertex, parentDestination);
		layoutModel.set(childVertex, childDestination);
		removeOldVertexAndEdges();

		updateOpacity(1D);

		controller.synchronizeProgramLocationAfterEdit();

		restoreEdgeDisplayAttributes();

		viewer.repaint();
	}

	private void restoreEdgeDisplayAttributes() {

		Iterable<FGEdge> edges =
			IterableUtils.chainedIterable(getEdges(parentVertex), getEdges(childVertex));
		for (FGEdge edge : edges) {
			double alpha = edge.getDefaultAlpha();
			edge.setAlpha(alpha);
		}
	}

	public void setPercentComplete(double percentComplete) {
		trace("setPercentComplete() callback: " + percentComplete);
		updateNewVertexPositions(percentComplete);
		updateOpacity(percentComplete);
		viewer.repaint();
	}

	protected void clearLocationCache() {
		LayoutModel<FGVertex> jungLayout = viewer.getVisualizationModel().getLayoutModel();
		((Caching) jungLayout).clear();
	}

//==================================================================================================
// Private Methods
//==================================================================================================
	private void updateNewVertexPositions(double percentComplete) {
		//
		// The new position is some percentage of the distance between the start 
		// position and the destination position
		//
		double parentDestinationX = parentDestination.x;
		double parentDeltaX = (parentDestinationX - parentStart.x) * percentComplete;
		double childDestinationY = childDestination.y;
		double childDeltaY = (childDestinationY - childStart.y) * percentComplete;

		double childDestinationX = childDestination.x;
		double childDeltaX = (childDestinationX - childStart.x) * percentComplete;
		double parentDestinationY = parentDestination.y;
		double parentDeltaY = (parentDestinationY - parentStart.y) * percentComplete;

		double newParentX = parentStart.x + parentDeltaX;
		double newParentY = parentStart.y + parentDeltaY;

		double newChildX = childStart.x + childDeltaX;
		double newChildY = childStart.y+ childDeltaY;

		Point newParentLocation = Point.of(newParentX, newParentY);
		Point newChildLocation = Point.of(newChildX, newChildY);

		// this is needed for the edges to paint correctly, as they may be articulated
		layoutModel.set(parentVertex, newParentLocation);
		layoutModel.set(childVertex, newChildLocation);
//		parentVertex.setLocation(newParentLocation);
//		childVertex.setLocation(newChildLocation);

		clearLocationCache(); // the new values won't be read if we don't clear the cache
		layoutModel.set(parentVertex, newParentLocation);
		layoutModel.set(childVertex, newChildLocation);
	}

	private void initializeVertexLocations() {
		// 
		// We will create the new locations for the new parent and child vertices.  There will
		// be the initial (start) location for each one and the destination location for each
		// one.  This allows us to show a transition from the start to the destination point.
		//
		Point oldLocation = layoutModel.apply(toSplitVertex);
		Point2D oldLocationProperty = toSplitVertex.getLocation();
		Point parentLocation = oldLocation;
		Point2D parentLocationProperty = (Point2D) oldLocationProperty.clone();

		// Update the new parent node to compensate for its new size.  This code effectively 
		// moves the new vertex up to account for the fact that its overall height has been 
		// reduced.  This is necessary to prevent the vertex from moving down, as the location of
		// a vertex is based upon its center point.
		Rectangle originalBounds = toSplitVertex.getBounds();
		Rectangle newBounds = parentVertex.getBounds();
		int dy = (newBounds.height - originalBounds.height) >> 1;
		parentLocation = parentLocation.add(0, dy);

		parentStart = parentLocation;
		parentDestination = parentStart; // this vertex doesn't move
		childStart = parentStart; // this vertex starts at the same place as the parent

		parentVertex.setLocation(parentLocationProperty);
		layoutModel.set(parentVertex, parentLocation); // tell the graph the new location

		Point childStartLocation =parentLocation;
		childVertex.setLocation(oldLocationProperty);
		layoutModel.set(childVertex, childStartLocation); // tell the graph the new location

		// Move the new child vertex down and add space between it and its parent.
		Rectangle parentBounds = parentVertex.getBounds();
		double childY = childStartLocation.y + parentBounds.height +
			GraphViewerUtils.EXTRA_LAYOUT_ROW_SPACING;
		childDestination = Point.of(childStartLocation.x, childY);

		// note: due to the caching nature of some layouts, if we don't reset this, then 
		// some of our GUI calculations will be incorrect (like when we try to fit the 
		// satellite in it's window).  So, we always have to clear the cache when we set locations
		clearLocationCache();
	}

	private void updateOpacity(double percentComplete) {
		double oldComponentsAlpha = 1.0 - percentComplete;
		toSplitVertex.setAlpha(oldComponentsAlpha);

		Collection<FGEdge> edges = getEdges(toSplitVertex);
		for (FGEdge edge : edges) {

			// don't go past the alpha when removing
			double defaultAlpha = edge.getDefaultAlpha();
			double alpha = Math.min(oldComponentsAlpha, defaultAlpha);
			edge.setAlpha(alpha);
		}

		double newComponentsAlpha = percentComplete;
		parentVertex.setAlpha(newComponentsAlpha);
		childVertex.setAlpha(newComponentsAlpha);

		edges = getEdges(parentVertex);
		for (FGEdge edge : edges) {

			// don't go past the alpha when adding
			double defaultAlpha = edge.getDefaultAlpha();
			double alpha = Math.min(newComponentsAlpha, defaultAlpha);
			edge.setAlpha(alpha);
		}

		edges = getEdges(childVertex);
		for (FGEdge edge : edges) {
			// don't go past the alpha when adding
			double defaultAlpha = edge.getDefaultAlpha();
			double alpha = Math.min(newComponentsAlpha, defaultAlpha);
			edge.setAlpha(alpha);
		}
	}

	private Collection<FGEdge> getEdges(FGVertex vertex) {
		Graph<FGVertex, FGEdge> graph = layoutModel.getGraph();
		List<FGEdge> edges = new LinkedList<>();
		Collection<FGEdge> inEdges = graph.incomingEdgesOf(vertex);
		if (inEdges != null) {
			edges.addAll(inEdges);
		}

		Collection<FGEdge> outEdges = graph.outgoingEdgesOf(vertex);
		if (outEdges != null) {
			edges.addAll(outEdges);
		}

		return edges;
	}

	private void removeOldVertexAndEdges() {

		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph graph = functionGraphData.getFunctionGraph();
		graph.removeVertex(toSplitVertex);
	}
}
