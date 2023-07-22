CFLAGS = \
	-Ofast \
	-Werror \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-Wno-unused-result \
	$$(pkg-config --cflags freetype2)

CXXFLAGS = \
	-Ofast \
	-Werror \
	-Wall \
	-Wextra \
	-Wno-unused-parameter \
	-Wno-unused-result \
	-std=c++17 \
	$$(PKG_CONFIG_PATH=libcamera_prefix/lib/pkgconfig pkg-config --cflags libcamera)

LDFLAGS = \
	-s \
	-pthread \
	$$(pkg-config --static --libs freetype2) \
	$$(PKG_CONFIG_PATH=libcamera_prefix/lib/pkgconfig pkg-config --static --libs libcamera)

OBJS = \
	base64.o \
	camera.o \
	encoder.o \
	main.o \
	parameters.o \
	pipe.o \
	sensor_mode.o \
	text.o \
	window.o

LIBCAMERA = libcamera_prefix/lib/libcamera.a

all: exe

$(LIBCAMERA):
	cd libcamera \
	&& meson setup \
	-Dlc-compliance=disabled \
	-Dipas=raspberrypi \
	-Dpipelines=raspberrypi \
	--prefix=$(PWD)/libcamera_prefix \
	build \
	&& ninja -C build install

text_font.h: text_font.ttf
	xxd --include $< > text_font.h

%.o: %.c $(LIBCAMERA) text_font.h
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp $(LIBCAMERA)
	$(CXX) $(CXXFLAGS) -c $< -o $@

exe: $(OBJS)
	$(CXX) $^ $(LDFLAGS) -o $@
