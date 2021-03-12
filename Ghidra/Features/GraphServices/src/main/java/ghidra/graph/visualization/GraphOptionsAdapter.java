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
package ghidra.graph.visualization;

import ghidra.framework.options.Options;
import ghidra.service.graph.GraphDisplay;
import resources.ResourceManager;
import utilities.util.FileUtilities;

import java.awt.Color;
import java.io.IOException;
import java.io.InputStream;

/**
 * Class for managing  options. Wraps an {@code Options} delegate
 * Provides 'getters' for the {@code Options} delegate key/values
 */
public class GraphOptionsAdapter {

	public static final String DEFAULT_NAME = "Default Graph Display";

	protected Options delegate;

	private static final String PREFIX = DEFAULT_NAME + ".";

	/**
	 * values are color names or rgb in hex '0xFF0000' is red
	 */
	String SELECTED_VERTEX_COLOR = "selectedVertexColor";

	/**
	 * values are color names or rgb in hex '0xFF0000' is red
	 */
	String SELECTED_EDGE_COLOR = "selectedEdgeColor";

	/**
	 * values are defined as an enum in {@link GraphDisplay} class
	 */
	String INITIAL_LAYOUT_ALGORITHM = "initialLayoutAlgorithm";

	/**
	 * true or false
	 * may have no meaning for a different graph visualization library
	 */
	String DISPLAY_VERTICES_AS_ICONS = "displayVerticesAsIcons";

	/**
	 * values are defined as an enum in {@link GraphDisplay} class
	 * may have no meaning for a different graph visualization library
	 */
	String VERTEX_LABEL_POSITION = "vertexLabelPosition";

	/**
	 * {@code true} or {@code false}, whether edge selection via a mouse click is enabled.
	 * May not be supported by every graph visualization library
	 */
	String ENABLE_EDGE_SELECTION = "enableEdgeSelection";

	/**
	 * A comma-separated list of edge type names in priority order
	 */
	String EDGE_TYPE_PRIORITY_LIST = "edgeTypePriorityList";

	/**
	 * A comma-separated list of edge type names.
	 * Any hits (in order) will be considered a favored edge for the min-cross layout
	 * algorithms.
	 * May have no meaning with a different graph visualization library
	 */
	String FAVORED_EDGES = "favoredEdges";

	private boolean displayVerticesAsIcons = true;

	/**
	 * The EdgeType priority list used for Block and Code Graphs.
	 * These String values are used in the AttributedEdge EdgeType property
	 */
	private static String DEFAULT_EDGE_TYPE_PRIORITY_LIST =
			"Fall-Through,"+
					"Conditional-Return,"+
					"Unconditional-Jump,"+
					"Conditional-Jump,"+
					"Unconditional-Call,"+
					"Conditional-Call,"+
					"Terminator,"+
					"Computed,"+
					"Indirection,"+
					"Entry";

	/**
	 * The default favored edge used for Block and Code Graphs.
	 * These String values are used in the AttributedEdge EdgeType property
	 */
	private static String DEFAULT_FAVORED_EDGES = "Fall-Through";

	// default values to be set as initial values for the delegate
	private final GraphDisplay.Layout initialLayoutAlgorithm = GraphDisplay.Layout.HIERARCHICAL;
	private final String edgeTypePriorityList = DEFAULT_EDGE_TYPE_PRIORITY_LIST;
	private final String favoredEdges = DEFAULT_FAVORED_EDGES;
	private final GraphDisplay.Compass vertexLabelPosition = GraphDisplay.Compass.S;
	private final Color selectedVertexColor = Color.red;
	private final Color selectedEdgeColor = Color.red;
	private final boolean enableEdgeSelection = false;

	/**
	 * register options with default defined in this class
	 * @param options
	 */
	public GraphOptionsAdapter(Options options, String path) {
		this.delegate = options;
		Options subOptions = options.getOptions(path);
		subOptions.registerOption(SELECTED_VERTEX_COLOR,
					selectedVertexColor,
					null, "Set a preference for the color of selected vertices");
		subOptions.registerOption(SELECTED_EDGE_COLOR,
					selectedEdgeColor, null, "Set a preference for the color of selected edges");
		subOptions.registerOption(INITIAL_LAYOUT_ALGORITHM,
					initialLayoutAlgorithm, null, "Set a preference for the initial layout algorithm");
		subOptions.registerOption(VERTEX_LABEL_POSITION,
					vertexLabelPosition, null, "Set a preference for the position of vertex labels");
		subOptions.registerOption(ENABLE_EDGE_SELECTION,
					enableEdgeSelection,
					null, "Set a preference for allowing edge selection with the mouse");
		subOptions.registerOption(EDGE_TYPE_PRIORITY_LIST,
					edgeTypePriorityList, null, "Set a preference for the relative priority of EdgeType values");
		subOptions.registerOption(FAVORED_EDGES,
					favoredEdges, null, "Set a preference for any EdgeType(s) that should be favored during layout");
		subOptions.registerOption(DISPLAY_VERTICES_AS_ICONS,
					displayVerticesAsIcons, null, "Set a preference as to whether to display vertices as icons (true) or shapes (false)");
	}

	/**
	 *
	 * @return whether to display vertices as icons {@code true} or not {@code false}
	 */
	public boolean getDisplayVerticesAsIcons() {
		return this.delegate.getBoolean(PREFIX + DISPLAY_VERTICES_AS_ICONS, displayVerticesAsIcons);
	}

	/**
	 *
	 * @return the enum value to consider for the initial layout algorithm for a new Graph display
	 */
	public GraphDisplay.Layout getInitialLayout() {
		return this.delegate.getEnum(PREFIX + INITIAL_LAYOUT_ALGORITHM, initialLayoutAlgorithm);
	}

	/**
	 *
	 * @return a comma-separated list of EdgeType values used to sort edges during layout
	 */
	public String getEdgeTypePriorityList() {
		return this.delegate.getString(PREFIX + EDGE_TYPE_PRIORITY_LIST, edgeTypePriorityList);
	}

	/**
	 *
	 * @return a comma-separated list of EdgeType values used to prioritize certain edges during layout
	 */
	public String getFavoredEdges() {
		return this.delegate.getString(PREFIX + FAVORED_EDGES, favoredEdges);
	}

	/**
	 *
	 * @return the @{code Color} to use to highlight a selected vertex
	 */
	public Color getSelectedVertexColor() {
		return this.delegate.getColor(PREFIX + SELECTED_VERTEX_COLOR, selectedVertexColor);
	}

	/**
	 *
	 * @return the {@code Color} to use to highlight a selected edge
	 */
	public Color getSelectedEdgeColor() {
		return this.delegate.getColor(PREFIX + SELECTED_EDGE_COLOR, selectedEdgeColor);
	}

	/**
	 *
	 * @return {@code true} to allow edge selection with the mouse
	 */
	public boolean enableEdgeSelection() {
		return this.delegate.getBoolean(PREFIX + ENABLE_EDGE_SELECTION, enableEdgeSelection);
	}

	/**
	 *
	 * @return an enum value to use for positioning a vertex label relative to the vertex
	 */
	public GraphDisplay.Compass getVertexLabelPosition() {
		return this.delegate.getEnum(PREFIX + VERTEX_LABEL_POSITION, vertexLabelPosition);
	}

	/**
	 * Get the contents of text resource file.
	 * @param filename name of resource file.
	 * @return contents of resource file as string.
	 */
	private static String getResourceData(String filename) {
		try (InputStream is = ResourceManager.getResourceAsStream(filename)) {
			String text = FileUtilities.getText(is);
			return text;
		}
		catch (IOException e) {
			return "";
		}
	}

}
