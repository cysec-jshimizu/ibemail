COMPILER  = g++
CFLAGS    = -g -MMD -MP -Wall -Wextra -Winit-self -Wno-missing-field-initializers -std=c++11
LDFLAGS   = -L./lib -lmcl -lresolv
LIBS      = ./lib/libmimetic.a -lgmp -lcrypto -lssl
INCLUDE   = -I./include -I/usr/local/include
TARGET    = ./bin/$(shell basename `readlink -f .`)
SRCDIR    = ./source
ifeq "$(strip $(SRCDIR))" ""
  SRCDIR  = .
endif
SOURCES   = $(wildcard $(SRCDIR)/*.cpp)
OBJDIR    = ./obj
ifeq "$(strip $(OBJDIR))" ""
  OBJDIR  = .
endif
OBJECTS   = $(addprefix $(OBJDIR)/, $(notdir $(SOURCES:.cpp=.o)))
DEPENDS   = $(OBJECTS:.o=.d)

$(TARGET): $(OBJECTS) $(LIBS)
	$(COMPILER) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	-mkdir -p $(OBJDIR)
	$(COMPILER) $(CFLAGS) $(INCLUDE) -o $@ -c $<

all: clean $(TARGET)

clean:
	-rm -f $(OBJECTS) $(DEPENDS) $(TARGET)

install:
	rm -fv $(OBJDIR)/libibemailtmp.a
	ar r $(OBJDIR)/libibemailtmp.a $(OBJDIR)/*.o
	echo -n -e "create $(OBJDIR)/libibemail.a\naddlib $(OBJDIR)/libibemailtmp.a\naddlib lib/libmimetic.a\nsave\nend" | ar -M

-include $(DEPENDS)

