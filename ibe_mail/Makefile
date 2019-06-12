COMPILER  = g++
CFLAGS    = -g -MMD -MP -Wall -Wextra -Winit-self -Wno-missing-field-initializers -std=c++11
LDFLAGS   = -lmimetic -lmcl -lresolv
LIBS      = -lgmp -lcrypto
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
MAKELIB   = $(OBJDIR)/libibemail.a

$(TARGET): $(OBJECTS) $(LIBS)
	$(COMPILER) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	-mkdir -p $(OBJDIR)
	$(COMPILER) $(CFLAGS) $(INCLUDE) -o $@ -c $<

all: clean $(TARGET)

install:
	-rm -f $(MAKELIB)
	make $(TARGET)
	ar r $(MAKELIB) $(OBJECTS)

clean:
	-rm -f $(OBJECTS) $(DEPENDS) $(TARGET) $(MAKELIB)

-include $(DEPENDS)

