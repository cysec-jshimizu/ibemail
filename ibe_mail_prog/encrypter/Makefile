COMPILER  = g++
CFLAGS    = -g -MMD -MP -Wall -Wextra -Winit-self -Wno-missing-field-initializers -std=c++11
LDFLAGS   = -L./lib -libemail -lmcl -lresolv -lmimetic
LIBS      = -lgmp -lcrypto -lssl
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

-include $(DEPENDS)

