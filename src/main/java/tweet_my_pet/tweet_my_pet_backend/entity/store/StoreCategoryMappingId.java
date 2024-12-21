package tweet_my_pet.tweet_my_pet_backend.entity.store;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.Hibernate;

import java.util.Objects;

@Getter
@Setter
@Embeddable
public class StoreCategoryMappingId implements java.io.Serializable {
    private static final long serialVersionUID = -7479129836050331227L;
    @Column(name = "store_category_id", nullable = false)
    private Integer storeCategoryId;

    @Column(name = "store_id", nullable = false)
    private Long storeId;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) return false;
        StoreCategoryMappingId entity = (StoreCategoryMappingId) o;
        return Objects.equals(this.storeId, entity.storeId) &&
                Objects.equals(this.storeCategoryId, entity.storeCategoryId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(storeId, storeCategoryId);
    }

}