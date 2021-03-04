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

import static ghidra.graph.viewer.options.RelayoutOption.ALWAYS;
import static ghidra.graph.viewer.options.RelayoutOption.VERTEX_GROUPING_CHANGES;

import java.awt.geom.Point2D;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions;
import ghidra.graph.viewer.layout.LayoutPositions;
import ghidra.graph.viewer.options.RelayoutOption;
import ghidra.program.model.address.Address;
import ghidra.util.exception.AssertException;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.layout.util.Caching;
import org.jungrapht.visualization.selection.MutableSelectedState;
import org.jungrapht.visualization.selection.SelectedState;

public abstract class AbstractGroupingFunctionGraphJob extends AbstractFunctionGraphTransitionJob {

	protected final GroupedFunctionGraphVertex groupVertex;
	protected Set<FGVertex> verticesToBeRemoved;
	protected Set<FGVertex> newVertices;

	/**
	 * Whether to relayout, based upon user tool options.
	 */
	protected final boolean relayout;

	protected static Set<FGVertex> asSet(GroupedFunctionGraphVertex groupVertex) {
		Set<FGVertex> set = new HashSet<>();
		set.add(groupVertex);
		return set;
	}

	/**
	 * Constructor
	 * 
	 * @param controller the controller of the graph to be ungrouped
	 * @param groupVertex The group vertex to be ungrouped
	 * @param newVertices the vertices that will remain after the grouping/ungrouping process has
	 *                    completed
	 * @param verticesToRemove the vertices that will be removed from the graph after the 
	 *                         grouping/ungrouping process has completed
	 * @param relayoutOverride a boolean that when true signals to perform a layout <b>
	 * 		  	  			   regardless of the user's relayout options</b>.  This is required to
	 *                         perform a manual relayout.
	 * @param useAnimation whether to use animation
	 */
	AbstractGroupingFunctionGraphJob(FGController controller,
			GroupedFunctionGraphVertex groupVertex, Set<FGVertex> newVertices,
			Set<FGVertex> verticesToRemove, boolean relayoutOverride, boolean useAnimation) {

		super(controller, useAnimation);

		this.controller = controller;
		this.groupVertex = groupVertex;
		this.newVertices = new HashSet<>(newVertices);
		this.verticesToBeRemoved = new HashSet<>(verticesToRemove);

		updateOpacity(0D); // don't paint the new vertex or edges initially

		// don't animate if we have too many vertices in the graph
		if (graph.getVertexCount() >= TOO_BIG_TO_ANIMATE) {
			this.useAnimation = false;
		}

		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		RelayoutOption relayoutOption = options.getRelayoutOption();
		this.relayout = relayoutOption == VERTEX_GROUPING_CHANGES || relayoutOption == ALWAYS ||
			relayoutOverride;
	}

	@Override
	protected void finished() {
		super.finished();

		notifyGroupChange();

		removeOldVertexAndEdges();

		MutableSelectedState<FGVertex> pickedVertexState = viewer.getSelectedVertexState();
		pickedVertexState.clear();
		for (FGVertex vertex : getNewVertices()) {
			pickedVertexState.select(vertex, true);
		}

		// little extra help for GC
		getVerticesToBeRemoved().clear();
		getNewVertices().clear();
	}

	abstract protected void notifyGroupChange();

	protected LayoutPositions<FGVertex, FGEdge> updateDestinationLocations() {
		Set<FGVertex> ignore = new HashSet<>();
		ignore.addAll(getVerticesToBeRemoved());

		LayoutPositions<FGVertex, FGEdge> positions;
		if (relayout) {

			positions = calculateDefaultLayoutLocations(ignore);

			Map<FGVertex, Point> locations = positions.getVertexLocations();
			Point groupDestinationPoint = maybeGetGroupDestinationPoint(locations);
			if (groupDestinationPoint != null) {
				locations.put(groupVertex, groupDestinationPoint);
			}
		}
		else {
			//
			// Unusual Code Alert!: when not performing a relayout, we can't know what the
			//                      articulations should be.  So, just clear all articulations. 
			//                      The result is edge/vertex crossing, but it is better than
			//                      having articulations in the middle of nowhere. 
			//             
			//                      If we ever add the ability to refresh articulations by 
			//                      using the layout, then we can change that here (TODO).
			//
			positions = getCurrentLayoutLocations();
			Map<FGVertex, Point> currentLocations = positions.getVertexLocations();
			positions = LayoutPositions.createNewPositions(currentLocations,
				new HashMap<>());
		}

		// update the locations the preferred grouping locations (which may be empty)
		Map<FGVertex, Point> layoutLocations = positions.getVertexLocations();
		Point groupDestinationPoint = layoutLocations.get(groupVertex);
		Map<FGVertex, Point> groupingDestinationLocations =
			getGroupingDestinationLocations(relayout, groupDestinationPoint);

		Set<Entry<FGVertex, Point>> entrySet = groupingDestinationLocations.entrySet();
		for (Entry<FGVertex, Point> entry : entrySet) {
			FGVertex vertex = entry.getKey();
			Point location = entry.getValue();
			layoutLocations.put(vertex, location);
		}

		return positions;
	}

	/*
	 * Subclasses must return locations for vertices.  This method will be called when no 
	 * relayout will be performed.
	 * 
	 * @return default destination locations for vertices
	 */
	protected abstract Map<FGVertex, Point> getGroupingDestinationLocations(boolean isRelayout,
			Point groupVertexDestinationLocation);

	protected Collection<FGVertex> getVerticesToMove() {
		Collection<FGVertex> graphVertices = graph.getVertices();
		if (relayout) {
			return new HashSet<>(graphVertices);
		}

		HashSet<FGVertex> set = new HashSet<>(groupVertex.getVertices());

		// this needs to be in intersection of group vertices with those still in the graph, as the
		// group vertices may no longer be in the graph, such as when adding to an existing group
		set.retainAll(graphVertices);
		return set;
	}

	protected Set<FGVertex> getVerticesToBeRemoved() {
		return verticesToBeRemoved;
	}

	protected Set<FGVertex> getNewVertices() {
		return newVertices;
	}

	@Override
	protected void updateOpacity(double percentComplete) {

		double oldComponentsAlpha = 1.0 - percentComplete;

		Collection<FGVertex> vertices = getVerticesToBeRemoved();
		for (FGVertex vertex : vertices) {

			vertex.setAlpha(oldComponentsAlpha);

			Collection<FGEdge> edges = getEdges(vertex);
			for (FGEdge edge : edges) {

				// don't go past the alpha when removing
				double defaultAlpha = edge.getDefaultAlpha();
				double alpha = Math.min(oldComponentsAlpha, defaultAlpha);
				edge.setAlpha(alpha);
			}
		}

		double newComponentsAlpha = percentComplete;
		vertices = getNewVertices();
		for (FGVertex vertex : vertices) {
			vertex.setAlpha(newComponentsAlpha);

			Collection<FGEdge> edges = getEdges(vertex);
			for (FGEdge edge : edges) {

				// don't go past the alpha when adding
				double defaultAlpha = edge.getDefaultAlpha();
				double alpha = Math.min(newComponentsAlpha, defaultAlpha);
				edge.setAlpha(alpha);
			}
		}
	}

	@Override
	protected void clearLocationCache() {
		LayoutModel<FGVertex> jungLayout = viewer.getVisualizationModel().getLayoutModel();
		((Caching) jungLayout).clear();
	}
//==================================================================================================
// Private Methods
//==================================================================================================	

	private void removeOldVertexAndEdges() {
		Collection<FGVertex> vertices = getVerticesToBeRemoved();
		graph.removeVertices(vertices);
	}

	private Point maybeGetGroupDestinationPoint(Map<FGVertex, Point> locations) {
		Set<FGVertex> toBeRemoved = getVerticesToBeRemoved();
		if (!toBeRemoved.contains(groupVertex)) {
			return null; // we are not removing the group vertex (must be a grouping operation)
		}

		// We want the group vertex to fade away into another vertex.  We also want to be 
		// consistent, so just merge to the root vertex of the group vertex.
		Address vertexAddress = groupVertex.getVertexAddress();
		Set<FGVertex> vertices = groupVertex.getVertices();
		for (FGVertex vertex : vertices) {
			if (vertex.containsAddress(vertexAddress)) {
				// just graph any vertex--we just need somewhere for the group to merge to
				Set<FGVertex> centerOverVertices = getNewVertices();
				return locations.get(centerOverVertices.iterator().next());
			}
		}

		throw new AssertException(
			"How did we not have a grouped vertex with the same address as the group vertex?");
	}
}
