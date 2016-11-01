var csgoegg = {};

csgoegg.init = function() {
	csgoegg.homeFiltering();
	csgoegg.copyColor();
};

csgoegg.copyColor = function() {
	$('.js-copy-color').on("click", function(e){
		e.preventDefault;
		alert("TODO: Copy Color!");
	});
}

csgoegg.homeFiltering = function() {
	// init Isotope
	var $grid = $('.js-filterable-events').isotope({
		// options
	});
	
	// filter items on button click
	$('.js-filter').on('click', function(e) {
		e.preventDefault();
		var filterValue = $(this).attr('data-filter');

		if(filterValue != "*"){
			filterValue = "." + filterValue;
		}

		$grid.isotope({ filter: filterValue });
	});
}

$(function() { csgoegg.init(); });
