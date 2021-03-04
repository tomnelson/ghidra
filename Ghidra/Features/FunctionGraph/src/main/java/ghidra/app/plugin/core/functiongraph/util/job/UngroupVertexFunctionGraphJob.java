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

import java.awt.geom.Point2D;
import java.util.*;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.graph.viewer.layout.LayoutPositions;
import org.jungrapht.visualization.layout.model.Point;

public class UngroupVertexFunctionGraphJob extends AbstractGroupingFunctionGraphJob {

	/**
	 * Constructor
	 * 
	 * @param controller the controller of the graph to be ungrouped
	 * @param groupVertex The group vertex to be ungrouped
	 * @param useAnimation whether to use animation
	 * @param isPartOfUngroupAll true signals that this ungroup is part of a larger ungrouping
	 *                           process
	 */
	public UngroupVertexFunctionGraphJob(FGController controller,
			GroupedFunctionGraphVertex groupVertex, boolean useAnimation,
			boolean isPartOfUngroupAll) {
		super(controller, groupVertex, groupVertex.getVertices(), asSet(groupVertex), false,
			useAnimation);
		this.duration = isPartOfUngroupAll ? FAST_DURATION : NORMAL_DURATION;
	}

//==================================================================================================
// Required Template Methods
//==================================================================================================	

	@Override
	protected void notifyGroupChange() {
		getFunctionGraph().groupRemoved(groupVertex);
	}

	@Override
	protected Map<FGVertex, Point> getGroupingDestinationLocations(boolean isRelayout,
																   Point groupVertexDestinationLocation) {

		if (isRelayout) {
			// We do not want to specify destination locations when a relayout is taking place. This
			// has the effect of letting the layout determine the best locations.
			return Collections.emptyMap();
		}

		// note: we don't need to worry about the group vertex here, as its position doesn't change
		return groupVertex.getPreGroupLocations();
	}

	@Override
	protected void initializeVertexLocations() {

		//
		// This may be the same as the current locations, or they may be updated, depending upon
		// user options
		// 
		LayoutPositions<FGVertex, FGEdge> positions = updateDestinationLocations();
		Map<FGVertex, Point> vertexDestinationLocations = positions.getVertexLocations();
		finalEdgeArticulations = positions.getEdgeArticulations();

		//
		// We want the vertices to start at the group vertex's current position and end 
		// up at their new location; to start at/behind the group vertex and then move
		// outward toward their final location.  
		//
		Point oldLocation = toLocation(groupVertex);
		Point groupVertexPoint = oldLocation;

		//
		// This group of vertices (all those besides the 'verticesToBeRemoved') will be moved
		// to either 1) their new layout positions, or 2) they will stay just where they are.  The
		// 'verticesToBeRemoved' will always be moved somewhere, depending upon the 'relayout' 
		// variable.
		//
		Collection<FGVertex> vertices = getVerticesToMove();
		for (FGVertex vertex : vertices) {

			Point currentPoint;
			if (newVertices.contains(vertex)) {
				// not in the layout yet, we have to use the group as the starting point
				currentPoint = groupVertexPoint;
			}
			else {
				currentPoint = toLocation(vertex);
			}

			Point startPoint =currentPoint;
			Point destinationPoint =  vertexDestinationLocations.get(vertex);
			TransitionPoints transitionPoints = new TransitionPoints(startPoint, destinationPoint);
			vertexLocations.put(vertex, transitionPoints);
		}

		for (FGVertex vertex : newVertices) {
			Point startPoint = groupVertexPoint;
			TransitionPoints xPoint = vertexLocations.get(vertex);
			xPoint.startPoint = startPoint;
		}

		//
		// We have to move edge articulations--create transition points. Depending upon the 
		// value of 'relayout', there may be no edges to update.
		//
		Map<FGEdge, List<Point>> edgeArticulations = positions.getEdgeArticulations();
		Collection<FGEdge> edgesToMove = graph.getEdges();
		for (FGEdge edge : edgesToMove) {
			List<Point> currentArticulations = edge.getArticulationPoints();
			List<Point> newArticulations = edgeArticulations.get(edge);
			if (newArticulations == null) {
				newArticulations = Collections.emptyList();
			}

			List<ArticulationTransitionPoints> transitionPoints = getArticulationTransitionPoints(
				currentArticulations, newArticulations, vertexDestinationLocations, edge);

			edgeArticulationLocations.put(edge, transitionPoints);
		}
	}

	private List<ArticulationTransitionPoints> getArticulationTransitionPoints(
			List<Point> currentArticulations, List<Point> newArticulations,
			Map<FGVertex, Point> destinationLocations, FGEdge edge) {

		if (currentArticulations.size() > newArticulations.size()) {
			return getArticulationTransitionPointsWhenStartingWithMorePoints(currentArticulations,
				newArticulations, destinationLocations, edge);
		}
		return getArticulationTransitionPointsWhenStartingWithLessPoints(currentArticulations,
			newArticulations, destinationLocations, edge);
	}

	private List<ArticulationTransitionPoints> getArticulationTransitionPointsWhenStartingWithMorePoints(
			List<Point> currentArticulations, List<Point> newArticulations,
			Map<FGVertex, Point> destinationLocations, FGEdge edge) {

		List<ArticulationTransitionPoints> transitionPoints = new ArrayList<>();

		for (int i = 0; i < currentArticulations.size(); i++) {

			Point startPoint = currentArticulations.get(i);
			Point endPoint = startPoint;
			if (i < newArticulations.size()) {
				// prefer the new articulations, while we have some
				endPoint = newArticulations.get(i);
			}
			else {
				// less articulations in the new layout--map to the destination point of the
				// destination vertex
				FGVertex destinationVertex = edge.getEnd();
				TransitionPoints destionationTranstionPoint =
					getTransitionPoint(vertexLocations, destinationLocations, destinationVertex);
				endPoint = destionationTranstionPoint.destinationPoint;
			}

			transitionPoints.add(new ArticulationTransitionPoints(startPoint, endPoint));
		}

		return transitionPoints;
	}

	private List<ArticulationTransitionPoints> getArticulationTransitionPointsWhenStartingWithLessPoints(
			List<Point> currentArticulations, List<Point> newArticulations,
			Map<FGVertex, Point> destinationLocations, FGEdge edge) {

		List<ArticulationTransitionPoints> transitionPoints = new ArrayList<>();

		// 
		// In this case we will have to add articulations to the current edge now so that we can
		// animate their creation.
		//
		List<Point> newStartArticulationsPoints = new ArrayList<>();

		// default to start vertex so to handle the case where we started with no articulations
		Point lastValidStartPoint = toLocation(edge.getStart());
		for (int i = 0; i < newArticulations.size(); i++) {
			Point endPoint = newArticulations.get(i);

			Point startPoint = lastValidStartPoint;
			if (i < currentArticulations.size()) {
				// prefer the new articulations, while we have some
				startPoint = currentArticulations.get(i);
				lastValidStartPoint = startPoint;
			}

			transitionPoints.add(new ArticulationTransitionPoints(startPoint, endPoint));
			newStartArticulationsPoints.add(startPoint);
		}

		edge.setArticulationPoints(newStartArticulationsPoints);

		return transitionPoints;
	}

	private TransitionPoints getTransitionPoint(Map<FGVertex, TransitionPoints> transitionPoints,
			Map<FGVertex, Point> destinationLocations, FGVertex vertex) {

		// make sure the original vertex is in the graph (it may have been grouped)
		FunctionGraph fg = getFunctionGraph();
		List<FGVertex> ignore = Arrays.asList(groupVertex);
		vertex = fg.findMatchingVertex(vertex, ignore);
		TransitionPoints transtionPoint = transitionPoints.get(vertex);
		if (transtionPoint != null) {
			return transtionPoint;
		}

		// We have a destination vertex that is not being moved, so it is not
		// in the 'transitionPoints'.  Create a TransitionPoint for it.
		return createTransitionPoint(destinationLocations, vertex);
	}

	private TransitionPoints createTransitionPoint(Map<FGVertex, Point> destinationLocations,
			FGVertex vertex) {
		Point currentPoint = toLocation(vertex);
		Point startPoint = currentPoint;

		Point endPoint = destinationLocations.get(vertex);
		if (endPoint == null) {
			// this can happen when the vertex is the group vertex being removed; just 
			// use the start point
			endPoint = startPoint;
		}

		Point destinationPoint = endPoint;
		return new TransitionPoints(startPoint, destinationPoint);
	}
}
