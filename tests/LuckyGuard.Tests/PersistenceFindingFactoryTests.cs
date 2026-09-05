using LuckyGuard.Core.Detection;
using LuckyGuard.Windows.Persistence;

namespace LuckyGuard.Tests;

public sealed class PersistenceFindingFactoryTests
{
    [Fact]
    public void ExtraRegistryViewEvidence_IsPreserved()
    {
        var finding = PersistenceFindingFactory.FromCommand(
            "LG.PERSISTENCE.RUN_COMMAND", "run", "CurrentUser\\Software\\X::Bad",
            "powershell -WindowStyle Hidden -EncodedCommand AAAA https://luckyware.cy/x",
            extraEvidence: [new Evidence("registryView", "Registry32")]);

        Assert.NotNull(finding);
        Assert.Contains(finding!.Evidence!, e => e.Kind == "registryView" && e.Value == "Registry32");
    }
}
