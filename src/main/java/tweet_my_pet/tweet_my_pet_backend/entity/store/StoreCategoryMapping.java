package tweet_my_pet.tweet_my_pet_backend.entity.store;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "store_category_mapping")
public class StoreCategoryMapping {
    @EmbeddedId
    private StoreCategoryMappingId id;

    @MapsId("storeCategoryId")
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "store_category_id", nullable = false)
    private StoreCategory storeCategory;

    @MapsId("storeId")
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "store_id", nullable = false)
    private Store store;

}