module.exports = function(grunt) {
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    concat: {
      options: {
        separator: ';'
      },
      dist: {
        src: ['dev/js/vendor/isotope.pkgd.js', 'dev/js/app.js'],
        dest: 'public/js/<%= pkg.name %>.js'
      }
    },
    uglify: {
      options: {
        banner: '/*! <%= pkg.name %> <%= grunt.template.today("dd-mm-yyyy") %> */\n'
      },
      dist: {
        files: {
          'public/js/<%= pkg.name %>.min.js': ['<%= concat.dist.dest %>']
        }
      }
    },
    jshint: {
      files: ['Gruntfile.js', 'dev/js/**/*.js'],
      options: {
        // options here to override JSHint defaults
        globals: {
          jQuery: true,
          console: true,
          module: true,
          document: true
        }
      }
    },
    sass: {
      options: {
        sourceMap: false
      },
      dist: {
        files: {
          'public/css/app.css':'dev/scss/app.scss'
        }
      }
    },
    postcss: {
      options: {
        map: {
            inline: false,
            annotation: 'public/css/maps/'
        },
        processors: [
          require('pixrem')(), // add fallbacks for rem units
          require('autoprefixer')({browsers: 'last 2 versions, not ie <= 8'}),
          require('cssnano')()
        ]
      },
      dist: {
        src: 'public/css/app.css'
      }
    },
    imagemin: {
      dynamic: {
        files: [{
          expand: true,
          cwd: 'dev/images/',
          src: ['**/*.{png,jpg,gif}'],
          dest: 'public/images/'
        }]
      }
    },
    copy: {
      main: {
        files: [
          {expand: true, flatten: true, src: ['dev/fonts/**'], dest: 'public/fonts/'}
        ]
      }
    },
    watch: {
      options: {
        livereload: true
      },
      files: ['<%= concat.dist.src %>', 'dev/scss/**/*.scss'],
      tasks: ['concat', 'uglify', 'sass', 'postcss']
    }
  });

  grunt.loadNpmTasks('grunt-contrib-uglify');
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-contrib-concat');
  grunt.loadNpmTasks('grunt-sass');
  grunt.loadNpmTasks('grunt-postcss');
  grunt.loadNpmTasks('grunt-contrib-imagemin');
  grunt.loadNpmTasks('grunt-contrib-copy');

  grunt.registerTask('default', ['concat', 'uglify', 'sass', 'postcss', 'copy']);
  grunt.registerTask('compress-images', ['imagemin']);

  grunt.registerTask('w', ['watch']);
  grunt.registerTask('production', ['default', 'compress-images']);
};
